// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package boot

import (
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	devtmpfsimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	goferimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	procimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	sysimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	tmpfsimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func vfs2SetupContainerFS(ctx context.Context, conf *Config, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	log.Infof("vfs2SetupContainerFS")
	if err := mntr.k.VFS().Init(); err != nil {
		return fmt.Errorf("failed to initialize VFS; %v", err)
	}
	mns, err := mntr.vfs2SetupFS(ctx, conf, procArgs)
	procArgs.MountNamespaceVFS2 = mns
	return err
}

// processHints processes annotations that container hints about how volumes
// should be mounted (e.g. a volume shared between containers). It must be
// called for the root container only.
func (c *containerMounter) vfs2ProcessHints(conf *Config) error {
	return nil
}

func (c *containerMounter) vfs2SetupFS(ctx context.Context, conf *Config, procArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
	log.Infof("Configuring container's file system")

	// Create context with root credentials to mount the filesystem (the current
	// user may not be privileged enough).
	rootProcArgs := *procArgs
	rootProcArgs.WorkingDirectory = "/"
	rootProcArgs.Credentials = auth.NewRootCredentials(procArgs.Credentials.UserNamespace)
	rootProcArgs.Umask = 0022
	rootProcArgs.MaxSymlinkTraversals = linux.MaxSymlinkTraversals
	rootCtx := procArgs.NewContext(c.k)

	creds := procArgs.Credentials
	if err := registerFilesystems(rootCtx, c.k.VFS(), creds); err != nil {
		return nil, fmt.Errorf("register filesystems: %v", err)
	}

	fd := c.fds.remove()
	s := []string{}

	s = append(s, "trans=fd",
		fmt.Sprintf("rfdno=%d", fd),
		fmt.Sprintf("wfdno=%d", fd),
		"cache=remote_revalidating",
	)
	opts := strings.Join(s, ",")

	log.Infof("Mounting root over 9P, ioFD: %d", fd)
	mns, err := c.k.VFS().NewMountNamespace(ctx, creds, "", rootFsName, &vfs.GetFilesystemOptions{Data: opts})
	if err != nil {
		return nil, fmt.Errorf("setting up mountnamespace: %v", err)
	}

	rootProcArgs.MountNamespaceVFS2 = mns

	// Mount submounts.
	if err := c.vfsMountSubmounts(rootCtx, conf, mns, creds); err != nil {
		return nil, fmt.Errorf("mounting submounts: %v", err)
	}

	return mns, nil
}

func (c *containerMounter) vfsMountSubmounts(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {

	for _, submount := range c.mounts {
		log.Debugf("Mounting %q to %q, type: %s, options: %s", submount.Source, submount.Destination, submount.Type, submount.Options)
		if err := c.vfsMountSubmount(ctx, conf, mns, creds, &submount); err != nil {
			return err
		}
	}

	// MountTmp maybe.
	/*
		 * if err := c.vfsMountTmp(ctx, conf, mns, root); err != nil {
			return fmt.Errorf("mount submount %q: %v", "tmp", err)
		}
	*/

	if err := c.checkDispenser(); err != nil {
		return err
	}
	return nil
}

func (c *containerMounter) vfsMountSubmount(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *specs.Mount) error {
	root := mns.Root()
	defer root.DecRef()
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(submount.Destination),
	}

	_, s, _, err := c.getMountNameAndOptions(conf, *submount)
	if err != nil {
		return fmt.Errorf("mountOptions failed: %v", err)
	}

	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: strings.Join(s, ","),
		},
		InternalMount: true,
	}

	if err := c.k.VFS().MountAt(ctx, creds, "", target, submount.Type, opts); err != nil {
		return fmt.Errorf("failed to mount %q (type: %s): %v", submount.Destination, submount.Type, err)
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q", submount.Source, submount.Destination, submount.Type, opts)
	return nil
}

func registerFilesystems(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) error {

	vfsObj.MustRegisterFilesystemType(rootFsName, &goferimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
	})

	vfsObj.MustRegisterFilesystemType(bind, &goferimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
	})

	vfsObj.MustRegisterFilesystemType(devpts, &devtmpfsimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	vfsObj.MustRegisterFilesystemType(devtmpfs, &devtmpfsimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(proc, &procimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(sysfs, &sysimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(tmpfs, &tmpfsimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(nonefs, &sysimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	// Setup files in devtmpfs.
	if err := memdev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering memdev: %v", err)
	}
	a, err := devtmpfsimpl.NewAccessor(ctx, vfsObj, creds, devtmpfsimpl.Name)
	if err != nil {
		return fmt.Errorf("creating devtmpfs accessor: %v", err)
	}
	defer a.Release()

	if err := a.UserspaceInit(ctx); err != nil {
		return fmt.Errorf("initializing userspace: %v", err)
	}
	if err := memdev.CreateDevtmpfsFiles(ctx, a); err != nil {
		return fmt.Errorf("creating devtmpfs files: %v", err)
	}
	return nil
}
