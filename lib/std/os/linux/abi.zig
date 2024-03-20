
pub fn dup(old: fd_t) ReturnCode {
    return SYS.dup.call1(arg(old));
}

pub fn dup2(old: fd_t, new: fd_t) ReturnCode {
    if (@hasField(SYS, "dup2")) {
        return SYS.dup2.call2(arg(old), arg(new));
    } else {
        if (old == new) {
            if (std.debug.runtime_safety) {
                const rc = SYS.fcntl.call2(arg(old), F.GETFD);
                if (rc.toSigned() < 0) return rc;
            }
            return ReturnCode.fromSigned(old);
        } else {
            return SYS.dup3.call3(arg(old), arg(new), 0);
        }
    }
}

pub fn dup3(old: fd_t, new: fd_t, flags: u32) usize {
    return SYS.dup3.call3(arg(old), arg(new), flags);
}

pub fn chdir(path: [*:0]const u8) usize {
    return syscall1(.chdir, @intFromPtr(path));
}

pub fn fchdir(fd: fd_t) usize {
    return syscall1(.fchdir, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn chroot(path: [*:0]const u8) usize {
    return syscall1(.chroot, @intFromPtr(path));
}

pub fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) usize {
    return syscall3(.execve, @intFromPtr(path), @intFromPtr(argv), @intFromPtr(envp));
}

pub fn fork() usize {
    if (comptime native_arch.isSPARC()) {
        return syscall_fork();
    } else if (@hasField(SYS, "fork")) {
        return syscall0(.fork);
    } else {
        return syscall2(.clone, SIG.CHLD, 0);
    }
}

/// This must be inline, and inline call the syscall function, because if the
/// child does a return it will clobber the parent's stack.
/// It is advised to avoid this function and use clone instead, because
/// the compiler is not aware of how vfork affects control flow and you may
/// see different results in optimized builds.
pub inline fn vfork() usize {
    return @call(.always_inline, syscall0, .{.vfork});
}

pub fn futimens(fd: i32, times: *const [2]timespec) usize {
    return utimensat(fd, null, times, 0);
}

pub fn utimensat(dirfd: i32, path: ?[*:0]const u8, times: *const [2]timespec, flags: u32) usize {
    return syscall4(.utimensat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(times), flags);
}

pub fn fallocate(fd: i32, mode: i32, offset: i64, length: i64) usize {
    if (usize_bits < 64) {
        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(length);
        return syscall6(
            .fallocate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(@as(isize, mode))),
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
        );
    } else {
        return syscall4(
            .fallocate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(@as(isize, mode))),
            @as(u64, @bitCast(offset)),
            @as(u64, @bitCast(length)),
        );
    }
}

pub fn futex_wait(uaddr: *const i32, futex_op: u32, val: i32, timeout: ?*const timespec) usize {
    return syscall4(.futex, @intFromPtr(uaddr), futex_op, @as(u32, @bitCast(val)), @intFromPtr(timeout));
}

pub fn futex_wake(uaddr: *const i32, futex_op: u32, val: i32) usize {
    return syscall3(.futex, @intFromPtr(uaddr), futex_op, @as(u32, @bitCast(val)));
}

/// Given an array of `futex_waitv`, wait on each uaddr.
/// The thread wakes if a futex_wake() is performed at any uaddr.
/// The syscall returns immediately if any waiter has *uaddr != val.
/// timeout is an optional timeout value for the operation.
/// Each waiter has individual flags.
/// The `flags` argument for the syscall should be used solely for specifying
/// the timeout as realtime, if needed.
/// Flags for private futexes, sizes, etc. should be used on the
/// individual flags of each waiter.
///
/// Returns the array index of one of the woken futexes.
/// No further information is provided: any number of other futexes may also
/// have been woken by the same event, and if more than one futex was woken,
/// the retrned index may refer to any one of them.
/// (It is not necessaryily the futex with the smallest index, nor the one
/// most recently woken, nor...)
pub fn futex2_waitv(
    /// List of futexes to wait on.
    waiters: [*]futex_waitv,
    /// Length of `waiters`.
    nr_futexes: u32,
    /// Flag for timeout (monotonic/realtime).
    flags: u32,
    /// Optional absolute timeout.
    timeout: ?*const timespec,
    /// Clock to be used for the timeout, realtime or monotonic.
    clockid: i32,
) usize {
    return syscall6(
        .futex_waitv,
        @intFromPtr(waiters),
        nr_futexes,
        flags,
        @intFromPtr(timeout),
        @bitCast(@as(isize, clockid)),
    );
}

/// Wait on a futex.
/// Identical to `FUTEX.WAIT`, except it is part of the futex2 family of calls.
pub fn futex2_wait(
    /// Address of the futex to wait on.
    uaddr: *const anyopaque,
    /// Value of `uaddr`.
    val: usize,
    /// Bitmask.
    mask: usize,
    /// `FUTEX2` flags.
    flags: u32,
    /// Optional absolute timeout.
    timeout: *const timespec,
    /// Clock to be used for the timeout, realtime or monotonic.
    clockid: i32,
) usize {
    return syscall6(
        .futex_wait,
        @intFromPtr(uaddr),
        val,
        mask,
        flags,
        @intFromPtr(timeout),
        @bitCast(@as(isize, clockid)),
    );
}

/// Wake a number of futexes.
/// Identical to `FUTEX.WAKE`, except it is part of the futex2 family of calls.
pub fn futex2_wake(
    /// Address of the futex(es) to wake.
    uaddr: [*]const anyopaque,
    /// Bitmask
    mask: usize,
    /// Number of the futexes to wake.
    nr: i32,
    /// `FUTEX2` flags.
    flags: u32,
) usize {
    return syscall4(
        .futex_wake,
        @intFromPtr(uaddr),
        mask,
        @bitCast(@as(isize, nr)),
        flags,
    );
}

/// Requeue a waiter from one futex to another.
/// Identical to `FUTEX.CMP_REQUEUE`, except it is part of the futex2 family of calls.
pub fn futex2_requeue(
    /// Array describing the source and destination futex.
    waiters: [*]futex_waitv,
    /// Unsed.
    flags: u32,
    /// Number of futexes to wake.
    nr_wake: i32,
    /// Number of futexes to requeue.
    nr_requeue: i32,
) usize {
    return syscall4(
        .futex_requeue,
        @intFromPtr(waiters),
        flags,
        @bitCast(@as(isize, nr_wake)),
        @bitCast(@as(isize, nr_requeue)),
    );
}

pub fn getcwd(buf: [*]u8, size: usize) usize {
    return syscall2(.getcwd, @intFromPtr(buf), size);
}

pub fn getdents(fd: i32, dirp: [*]u8, len: usize) usize {
    return syscall3(
        .getdents,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(dirp),
        @min(len, maxInt(c_int)),
    );
}

pub fn getdents64(fd: i32, dirp: [*]u8, len: usize) usize {
    return syscall3(
        .getdents64,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(dirp),
        @min(len, maxInt(c_int)),
    );
}

pub fn inotify_init1(flags: u32) usize {
    return syscall1(.inotify_init1, flags);
}

pub fn inotify_add_watch(fd: i32, pathname: [*:0]const u8, mask: u32) usize {
    return syscall3(.inotify_add_watch, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(pathname), mask);
}

pub fn inotify_rm_watch(fd: i32, wd: i32) usize {
    return syscall2(.inotify_rm_watch, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, wd))));
}

pub fn fanotify_init(flags: u32, event_f_flags: u32) usize {
    return syscall2(.fanotify_init, flags, event_f_flags);
}

pub fn fanotify_mark(fd: i32, flags: u32, mask: u64, dirfd: i32, pathname: ?[*:0]const u8) usize {
    return syscall5(.fanotify_mark, @as(usize, @bitCast(@as(isize, fd))), flags, mask, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(pathname));
}

pub fn readlink(noalias path: [*:0]const u8, noalias buf_ptr: [*]u8, buf_len: usize) usize {
    if (@hasField(SYS, "readlink")) {
        return syscall3(.readlink, @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
    } else {
        return syscall4(.readlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
    }
}

pub fn readlinkat(dirfd: i32, noalias path: [*:0]const u8, noalias buf_ptr: [*]u8, buf_len: usize) usize {
    return syscall4(.readlinkat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(buf_ptr), buf_len);
}

pub fn mkdir(path: [*:0]const u8, mode: u32) usize {
    if (@hasField(SYS, "mkdir")) {
        return syscall2(.mkdir, @intFromPtr(path), mode);
    } else {
        return syscall3(.mkdirat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), mode);
    }
}

pub fn mkdirat(dirfd: i32, path: [*:0]const u8, mode: u32) usize {
    return syscall3(.mkdirat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode);
}

pub fn mknod(path: [*:0]const u8, mode: u32, dev: u32) usize {
    if (@hasField(SYS, "mknod")) {
        return syscall3(.mknod, @intFromPtr(path), mode, dev);
    } else {
        return mknodat(AT.FDCWD, path, mode, dev);
    }
}

pub fn mknodat(dirfd: i32, path: [*:0]const u8, mode: u32, dev: u32) usize {
    return syscall4(.mknodat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode, dev);
}

pub fn mount(special: [*:0]const u8, dir: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32, data: usize) usize {
    return syscall5(.mount, @intFromPtr(special), @intFromPtr(dir), @intFromPtr(fstype), flags, data);
}

pub fn umount(special: [*:0]const u8) usize {
    return syscall2(.umount2, @intFromPtr(special), 0);
}

pub fn umount2(special: [*:0]const u8, flags: u32) usize {
    return syscall2(.umount2, @intFromPtr(special), flags);
}

pub fn mmap(address: ?[*]u8, length: usize, prot: usize, flags: MAP, fd: i32, offset: i64) usize {
    if (@hasField(SYS, "mmap2")) {
        // Make sure the offset is also specified in multiples of page size
        if ((offset & (MMAP2_UNIT - 1)) != 0)
            return @bitCast(-@as(isize, @intFromEnum(E.INVAL)));

        return syscall6(
            .mmap2,
            @intFromPtr(address),
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @bitCast(@as(isize, fd)),
            @truncate(@as(u64, @bitCast(offset)) / MMAP2_UNIT),
        );
    } else {
        return syscall6(
            .mmap,
            @intFromPtr(address),
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @bitCast(@as(isize, fd)),
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn mprotect(address: [*]const u8, length: usize, protection: usize) usize {
    return syscall3(.mprotect, @intFromPtr(address), length, protection);
}

pub fn msync(address: [*]const u8, length: usize, flags: i32) usize {
    return syscall3(.msync, @intFromPtr(address), length, @as(u32, @bitCast(flags)));
}

pub fn munmap(address: [*]const u8, length: usize) usize {
    return syscall2(.munmap, @intFromPtr(address), length);
}

pub fn poll(fds: [*]pollfd, n: nfds_t, timeout: i32) usize {
    if (@hasField(SYS, "poll")) {
        return syscall3(.poll, @intFromPtr(fds), n, @as(u32, @bitCast(timeout)));
    } else {
        return syscall5(
            .ppoll,
            @intFromPtr(fds),
            n,
            @intFromPtr(if (timeout >= 0)
                &timespec{
                    .tv_sec = @divTrunc(timeout, 1000),
                    .tv_nsec = @rem(timeout, 1000) * 1000000,
                }
            else
                null),
            0,
            NSIG / 8,
        );
    }
}

pub fn ppoll(fds: [*]pollfd, n: nfds_t, timeout: ?*timespec, sigmask: ?*const sigset_t) usize {
    return syscall5(.ppoll, @intFromPtr(fds), n, @intFromPtr(timeout), @intFromPtr(sigmask), NSIG / 8);
}

pub fn read(fd: i32, buf: [*]u8, count: usize) usize {
    return syscall3(.read, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), count);
}

pub fn preadv(fd: i32, iov: [*]const iovec, count: usize, offset: i64) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall5(
        .preadv,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // Kernel expects the offset is split into largest natural word-size.
        // See following link for detail:
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=601cc11d054ae4b5e9b5babec3d8e4667a2cb9b5
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
    );
}

pub fn preadv2(fd: i32, iov: [*]const iovec, count: usize, offset: i64, flags: kernel_rwf) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall6(
        .preadv2,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
        flags,
    );
}

pub fn readv(fd: i32, iov: [*]const iovec, count: usize) usize {
    return syscall3(.readv, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(iov), count);
}

pub fn writev(fd: i32, iov: [*]const iovec_const, count: usize) usize {
    return syscall3(.writev, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(iov), count);
}

pub fn pwritev(fd: i32, iov: [*]const iovec_const, count: usize, offset: i64) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall5(
        .pwritev,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
    );
}

pub fn pwritev2(fd: i32, iov: [*]const iovec_const, count: usize, offset: i64, flags: kernel_rwf) usize {
    const offset_u: u64 = @bitCast(offset);
    return syscall6(
        .pwritev2,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(iov),
        count,
        // See comments in preadv
        @as(usize, @truncate(offset_u)),
        if (usize_bits < 64) @as(usize, @truncate(offset_u >> 32)) else 0,
        flags,
    );
}

pub fn rmdir(path: [*:0]const u8) usize {
    if (@hasField(SYS, "rmdir")) {
        return syscall1(.rmdir, @intFromPtr(path));
    } else {
        return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), AT.REMOVEDIR);
    }
}

pub fn symlink(existing: [*:0]const u8, new: [*:0]const u8) usize {
    if (@hasField(SYS, "symlink")) {
        return syscall2(.symlink, @intFromPtr(existing), @intFromPtr(new));
    } else {
        return syscall3(.symlinkat, @intFromPtr(existing), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new));
    }
}

pub fn symlinkat(existing: [*:0]const u8, newfd: i32, newpath: [*:0]const u8) usize {
    return syscall3(.symlinkat, @intFromPtr(existing), @as(usize, @bitCast(@as(isize, newfd))), @intFromPtr(newpath));
}

pub fn pread(fd: i32, buf: [*]u8, count: usize, offset: i64) usize {
    if (@hasField(SYS, "pread64") and usize_bits < 64) {
        const offset_halves = splitValue64(offset);
        if (require_aligned_register_pair) {
            return syscall6(
                .pread64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                0,
                offset_halves[0],
                offset_halves[1],
            );
        } else {
            return syscall5(
                .pread64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                offset_halves[0],
                offset_halves[1],
            );
        }
    } else {
        // Some architectures (eg. 64bit SPARC) pread is called pread64.
        const syscall_number = if (!@hasField(SYS, "pread") and @hasField(SYS, "pread64"))
            .pread64
        else
            .pread;
        return syscall4(
            syscall_number,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(buf),
            count,
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn access(path: [*:0]const u8, mode: u32) usize {
    if (@hasField(SYS, "access")) {
        return syscall2(.access, @intFromPtr(path), mode);
    } else {
        return syscall4(.faccessat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), mode, 0);
    }
}

pub fn faccessat(dirfd: i32, path: [*:0]const u8, mode: u32, flags: u32) usize {
    return syscall4(.faccessat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), mode, flags);
}

pub fn pipe(fd: *[2]i32) usize {
    if (comptime (native_arch.isMIPS() or native_arch.isSPARC())) {
        return syscall_pipe(fd);
    } else if (@hasField(SYS, "pipe")) {
        return syscall1(.pipe, @intFromPtr(fd));
    } else {
        return syscall2(.pipe2, @intFromPtr(fd), 0);
    }
}

pub fn pipe2(fd: *[2]i32, flags: O) usize {
    return syscall2(.pipe2, @intFromPtr(fd), @as(u32, @bitCast(flags)));
}

pub fn write(fd: fd_t, buf: [*]const u8, count: usize) ReturnCode {
    return SYS.write.call3(arg(fd), arg(buf), count);
}

pub fn ftruncate(fd: i32, length: i64) usize {
    if (@hasField(SYS, "ftruncate64") and usize_bits < 64) {
        const length_halves = splitValue64(length);
        if (require_aligned_register_pair) {
            return syscall4(
                .ftruncate64,
                @as(usize, @bitCast(@as(isize, fd))),
                0,
                length_halves[0],
                length_halves[1],
            );
        } else {
            return syscall3(
                .ftruncate64,
                @as(usize, @bitCast(@as(isize, fd))),
                length_halves[0],
                length_halves[1],
            );
        }
    } else {
        return syscall2(
            .ftruncate,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(length)),
        );
    }
}

pub fn pwrite(fd: i32, buf: [*]const u8, count: usize, offset: i64) usize {
    if (@hasField(SYS, "pwrite64") and usize_bits < 64) {
        const offset_halves = splitValue64(offset);

        if (require_aligned_register_pair) {
            return syscall6(
                .pwrite64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                0,
                offset_halves[0],
                offset_halves[1],
            );
        } else {
            return syscall5(
                .pwrite64,
                @as(usize, @bitCast(@as(isize, fd))),
                @intFromPtr(buf),
                count,
                offset_halves[0],
                offset_halves[1],
            );
        }
    } else {
        // Some architectures (eg. 64bit SPARC) pwrite is called pwrite64.
        const syscall_number = if (!@hasField(SYS, "pwrite") and @hasField(SYS, "pwrite64"))
            .pwrite64
        else
            .pwrite;
        return syscall4(
            syscall_number,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(buf),
            count,
            @as(u64, @bitCast(offset)),
        );
    }
}

pub fn rename(old: [*:0]const u8, new: [*:0]const u8) usize {
    if (@hasField(SYS, "rename")) {
        return syscall2(.rename, @intFromPtr(old), @intFromPtr(new));
    } else if (@hasField(SYS, "renameat")) {
        return syscall4(.renameat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(old), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new));
    } else {
        return syscall5(.renameat2, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(old), @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(new), 0);
    }
}

pub fn renameat(oldfd: i32, oldpath: [*:0]const u8, newfd: i32, newpath: [*:0]const u8) usize {
    if (@hasField(SYS, "renameat")) {
        return syscall4(
            .renameat,
            @as(usize, @bitCast(@as(isize, oldfd))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, newfd))),
            @intFromPtr(newpath),
        );
    } else {
        return syscall5(
            .renameat2,
            @as(usize, @bitCast(@as(isize, oldfd))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, newfd))),
            @intFromPtr(newpath),
            0,
        );
    }
}

pub fn renameat2(oldfd: i32, oldpath: [*:0]const u8, newfd: i32, newpath: [*:0]const u8, flags: u32) usize {
    return syscall5(
        .renameat2,
        @as(usize, @bitCast(@as(isize, oldfd))),
        @intFromPtr(oldpath),
        @as(usize, @bitCast(@as(isize, newfd))),
        @intFromPtr(newpath),
        flags,
    );
}

pub fn open(path: [*:0]const u8, flags: O, perm: mode_t) usize {
    if (@hasField(SYS, "open")) {
        return syscall3(.open, @intFromPtr(path), @as(u32, @bitCast(flags)), perm);
    } else {
        return syscall4(
            .openat,
            @bitCast(@as(isize, AT.FDCWD)),
            @intFromPtr(path),
            @as(u32, @bitCast(flags)),
            perm,
        );
    }
}

pub fn create(path: [*:0]const u8, perm: mode_t) usize {
    return syscall2(.creat, @intFromPtr(path), perm);
}

pub fn openat(dirfd: i32, path: [*:0]const u8, flags: O, mode: mode_t) usize {
    // dirfd could be negative, for example AT.FDCWD is -100
    return syscall4(.openat, @bitCast(@as(isize, dirfd)), @intFromPtr(path), @as(u32, @bitCast(flags)), mode);
}

/// See also `clone` (from the arch-specific include)
pub fn clone5(flags: usize, child_stack_ptr: usize, parent_tid: *i32, child_tid: *i32, newtls: usize) usize {
    return syscall5(.clone, flags, child_stack_ptr, @intFromPtr(parent_tid), @intFromPtr(child_tid), newtls);
}

/// See also `clone` (from the arch-specific include)
pub fn clone2(flags: u32, child_stack_ptr: usize) usize {
    return syscall2(.clone, flags, child_stack_ptr);
}

pub fn close(fd: i32) usize {
    return syscall1(.close, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fchmod(fd: i32, mode: mode_t) usize {
    return syscall2(.fchmod, @as(usize, @bitCast(@as(isize, fd))), mode);
}

pub fn chmod(path: [*:0]const u8, mode: mode_t) usize {
    if (@hasField(SYS, "chmod")) {
        return syscall2(.chmod, @intFromPtr(path), mode);
    } else {
        return fchmodat(AT.FDCWD, path, mode, 0);
    }
}

pub fn fchown(fd: i32, owner: uid_t, group: gid_t) usize {
    if (@hasField(SYS, "fchown32")) {
        return syscall3(.fchown32, @as(usize, @bitCast(@as(isize, fd))), owner, group);
    } else {
        return syscall3(.fchown, @as(usize, @bitCast(@as(isize, fd))), owner, group);
    }
}

pub fn fchmodat(fd: i32, path: [*:0]const u8, mode: mode_t, _: u32) usize {
    return syscall3(.fchmodat, @bitCast(@as(isize, fd)), @intFromPtr(path), mode);
}

pub fn fchmodat2(fd: i32, path: [*:0]const u8, mode: mode_t, flags: u32) usize {
    return syscall4(.fchmodat2, @bitCast(@as(isize, fd)), @intFromPtr(path), mode, flags);
}

/// Can only be called on 32 bit systems. For 64 bit see `lseek`.
pub fn llseek(fd: i32, offset: u64, result: ?*u64, whence: usize) usize {
    // NOTE: The offset parameter splitting is independent from the target
    // endianness.
    return syscall5(
        ._llseek,
        @as(usize, @bitCast(@as(isize, fd))),
        @as(usize, @truncate(offset >> 32)),
        @as(usize, @truncate(offset)),
        @intFromPtr(result),
        whence,
    );
}

/// Can only be called on 64 bit systems. For 32 bit see `llseek`.
pub fn lseek(fd: i32, offset: i64, whence: usize) usize {
    return syscall3(.lseek, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(offset)), whence);
}

pub fn exit(status: i32) noreturn {
    _ = syscall1(.exit, @as(usize, @bitCast(@as(isize, status))));
    unreachable;
}

pub fn exit_group(status: i32) noreturn {
    _ = syscall1(.exit_group, @as(usize, @bitCast(@as(isize, status))));
    unreachable;
}

pub fn reboot(magic: LINUX_REBOOT.MAGIC1, magic2: LINUX_REBOOT.MAGIC2, cmd: LINUX_REBOOT.CMD, argument: ?*const anyopaque) usize {
    return std.os.linux.syscall4(
        .reboot,
        @intFromEnum(magic),
        @intFromEnum(magic2),
        @intFromEnum(cmd),
        @intFromPtr(argument),
    );
}

pub fn getrandom(buf: [*]u8, count: usize, flags: u32) usize {
    return syscall3(.getrandom, @intFromPtr(buf), count, flags);
}

pub fn kill(pid: pid_t, sig: i32) usize {
    return syscall2(.kill, @as(usize, @bitCast(@as(isize, pid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn tkill(tid: pid_t, sig: i32) usize {
    return syscall2(.tkill, @as(usize, @bitCast(@as(isize, tid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn tgkill(tgid: pid_t, tid: pid_t, sig: i32) usize {
    return syscall3(.tgkill, @as(usize, @bitCast(@as(isize, tgid))), @as(usize, @bitCast(@as(isize, tid))), @as(usize, @bitCast(@as(isize, sig))));
}

pub fn link(oldpath: [*:0]const u8, newpath: [*:0]const u8, flags: i32) usize {
    if (@hasField(SYS, "link")) {
        return syscall3(
            .link,
            @intFromPtr(oldpath),
            @intFromPtr(newpath),
            @as(usize, @bitCast(@as(isize, flags))),
        );
    } else {
        return syscall5(
            .linkat,
            @as(usize, @bitCast(@as(isize, AT.FDCWD))),
            @intFromPtr(oldpath),
            @as(usize, @bitCast(@as(isize, AT.FDCWD))),
            @intFromPtr(newpath),
            @as(usize, @bitCast(@as(isize, flags))),
        );
    }
}

pub fn linkat(oldfd: fd_t, oldpath: [*:0]const u8, newfd: fd_t, newpath: [*:0]const u8, flags: i32) usize {
    return syscall5(
        .linkat,
        @as(usize, @bitCast(@as(isize, oldfd))),
        @intFromPtr(oldpath),
        @as(usize, @bitCast(@as(isize, newfd))),
        @intFromPtr(newpath),
        @as(usize, @bitCast(@as(isize, flags))),
    );
}

pub fn unlink(path: [*:0]const u8) usize {
    if (@hasField(SYS, "unlink")) {
        return syscall1(.unlink, @intFromPtr(path));
    } else {
        return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, AT.FDCWD))), @intFromPtr(path), 0);
    }
}

pub fn unlinkat(dirfd: i32, path: [*:0]const u8, flags: u32) usize {
    return syscall3(.unlinkat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), flags);
}

pub fn waitpid(pid: pid_t, status: *u32, flags: u32) usize {
    return syscall4(.wait4, @as(usize, @bitCast(@as(isize, pid))), @intFromPtr(status), flags, 0);
}

pub fn wait4(pid: pid_t, status: *u32, flags: u32, usage: ?*rusage) usize {
    return syscall4(
        .wait4,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(status),
        flags,
        @intFromPtr(usage),
    );
}

pub fn waitid(id_type: P, id: i32, infop: *siginfo_t, flags: u32) usize {
    return syscall5(.waitid, @intFromEnum(id_type), @as(usize, @bitCast(@as(isize, id))), @intFromPtr(infop), flags, 0);
}

pub fn fcntl(fd: fd_t, cmd: i32, argument: usize) usize {
    return syscall3(.fcntl, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, cmd))), argument);
}

pub fn flock(fd: fd_t, operation: i32) usize {
    return syscall2(.flock, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, operation))));
}

pub fn clock_gettime(clk_id: i32, tp: *timespec) usize {
    if (@hasDecl(VDSO, "CGT_SYM")) {
        const ptr = @atomicLoad(?VdsoClockGettime, &vdso_clock_gettime, .unordered);
        if (ptr) |f| {
            const rc = f(clk_id, tp);
            switch (rc) {
                0, @as(usize, @bitCast(-@as(isize, @intFromEnum(E.INVAL)))) => return rc,
                else => {},
            }
        }
    }
    return syscall2(.clock_gettime, @as(usize, @bitCast(@as(isize, clk_id))), @intFromPtr(tp));
}

pub fn clock_getres(clk_id: i32, tp: *timespec) usize {
    return syscall2(.clock_getres, @as(usize, @bitCast(@as(isize, clk_id))), @intFromPtr(tp));
}

pub fn clock_settime(clk_id: i32, tp: *const timespec) usize {
    return syscall2(.clock_settime, @as(usize, @bitCast(@as(isize, clk_id))), @intFromPtr(tp));
}

pub fn gettimeofday(tv: ?*timeval, tz: ?*timezone) usize {
    return syscall2(.gettimeofday, @intFromPtr(tv), @intFromPtr(tz));
}

pub fn settimeofday(tv: *const timeval, tz: *const timezone) usize {
    return syscall2(.settimeofday, @intFromPtr(tv), @intFromPtr(tz));
}

pub fn nanosleep(req: *const timespec, rem: ?*timespec) usize {
    return syscall2(.nanosleep, @intFromPtr(req), @intFromPtr(rem));
}

pub fn pause() usize {
    if (@hasField(SYS, "pause")) {
        return syscall0(.pause);
    } else {
        return syscall4(.ppoll, 0, 0, 0, 0);
    }
}

pub fn setuid(uid: uid_t) usize {
    if (@hasField(SYS, "setuid32")) {
        return syscall1(.setuid32, uid);
    } else {
        return syscall1(.setuid, uid);
    }
}

pub fn setgid(gid: gid_t) usize {
    if (@hasField(SYS, "setgid32")) {
        return syscall1(.setgid32, gid);
    } else {
        return syscall1(.setgid, gid);
    }
}

pub fn setreuid(ruid: uid_t, euid: uid_t) usize {
    if (@hasField(SYS, "setreuid32")) {
        return syscall2(.setreuid32, ruid, euid);
    } else {
        return syscall2(.setreuid, ruid, euid);
    }
}

pub fn setregid(rgid: gid_t, egid: gid_t) usize {
    if (@hasField(SYS, "setregid32")) {
        return syscall2(.setregid32, rgid, egid);
    } else {
        return syscall2(.setregid, rgid, egid);
    }
}

pub fn getuid() uid_t {
    if (@hasField(SYS, "getuid32")) {
        return @as(uid_t, @intCast(syscall0(.getuid32)));
    } else {
        return @as(uid_t, @intCast(syscall0(.getuid)));
    }
}

pub fn getgid() gid_t {
    if (@hasField(SYS, "getgid32")) {
        return @as(gid_t, @intCast(syscall0(.getgid32)));
    } else {
        return @as(gid_t, @intCast(syscall0(.getgid)));
    }
}

pub fn geteuid() uid_t {
    if (@hasField(SYS, "geteuid32")) {
        return @as(uid_t, @intCast(syscall0(.geteuid32)));
    } else {
        return @as(uid_t, @intCast(syscall0(.geteuid)));
    }
}

pub fn getegid() gid_t {
    if (@hasField(SYS, "getegid32")) {
        return @as(gid_t, @intCast(syscall0(.getegid32)));
    } else {
        return @as(gid_t, @intCast(syscall0(.getegid)));
    }
}

pub fn seteuid(euid: uid_t) usize {
    // We use setresuid here instead of setreuid to ensure that the saved uid
    // is not changed. This is what musl and recent glibc versions do as well.
    //
    // The setresuid(2) man page says that if -1 is passed the corresponding
    // id will not be changed. Since uid_t is unsigned, this wraps around to the
    // max value in C.
    comptime assert(@typeInfo(uid_t) == .Int and @typeInfo(uid_t).Int.signedness == .unsigned);
    return setresuid(std.math.maxInt(uid_t), euid, std.math.maxInt(uid_t));
}

pub fn setegid(egid: gid_t) usize {
    // We use setresgid here instead of setregid to ensure that the saved uid
    // is not changed. This is what musl and recent glibc versions do as well.
    //
    // The setresgid(2) man page says that if -1 is passed the corresponding
    // id will not be changed. Since gid_t is unsigned, this wraps around to the
    // max value in C.
    comptime assert(@typeInfo(uid_t) == .Int and @typeInfo(uid_t).Int.signedness == .unsigned);
    return setresgid(std.math.maxInt(gid_t), egid, std.math.maxInt(gid_t));
}

pub fn getresuid(ruid: *uid_t, euid: *uid_t, suid: *uid_t) usize {
    if (@hasField(SYS, "getresuid32")) {
        return syscall3(.getresuid32, @intFromPtr(ruid), @intFromPtr(euid), @intFromPtr(suid));
    } else {
        return syscall3(.getresuid, @intFromPtr(ruid), @intFromPtr(euid), @intFromPtr(suid));
    }
}

pub fn getresgid(rgid: *gid_t, egid: *gid_t, sgid: *gid_t) usize {
    if (@hasField(SYS, "getresgid32")) {
        return syscall3(.getresgid32, @intFromPtr(rgid), @intFromPtr(egid), @intFromPtr(sgid));
    } else {
        return syscall3(.getresgid, @intFromPtr(rgid), @intFromPtr(egid), @intFromPtr(sgid));
    }
}

pub fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) usize {
    if (@hasField(SYS, "setresuid32")) {
        return syscall3(.setresuid32, ruid, euid, suid);
    } else {
        return syscall3(.setresuid, ruid, euid, suid);
    }
}

pub fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) usize {
    if (@hasField(SYS, "setresgid32")) {
        return syscall3(.setresgid32, rgid, egid, sgid);
    } else {
        return syscall3(.setresgid, rgid, egid, sgid);
    }
}

pub fn getgroups(size: usize, list: *gid_t) usize {
    if (@hasField(SYS, "getgroups32")) {
        return syscall2(.getgroups32, size, @intFromPtr(list));
    } else {
        return syscall2(.getgroups, size, @intFromPtr(list));
    }
}

pub fn setgroups(size: usize, list: [*]const gid_t) usize {
    if (@hasField(SYS, "setgroups32")) {
        return syscall2(.setgroups32, size, @intFromPtr(list));
    } else {
        return syscall2(.setgroups, size, @intFromPtr(list));
    }
}

pub fn setsid() pid_t {
    return @as(pid_t, @bitCast(@as(u32, @truncate(syscall0(.setsid)))));
}

pub fn getpid() pid_t {
    return @as(pid_t, @bitCast(@as(u32, @truncate(syscall0(.getpid)))));
}

pub fn gettid() pid_t {
    return @as(pid_t, @bitCast(@as(u32, @truncate(syscall0(.gettid)))));
}

pub fn sigprocmask(flags: u32, noalias set: ?*const sigset_t, noalias oldset: ?*sigset_t) usize {
    return syscall4(.rt_sigprocmask, flags, @intFromPtr(set), @intFromPtr(oldset), NSIG / 8);
}

pub fn sigaction(sig: u6, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) usize {
    assert(sig >= 1);
    assert(sig != SIG.KILL);
    assert(sig != SIG.STOP);

    var ksa: k_sigaction = undefined;
    var oldksa: k_sigaction = undefined;
    const mask_size = @sizeOf(@TypeOf(ksa.mask));

    if (act) |new| {
        const restorer_fn = if ((new.flags & SA.SIGINFO) != 0) &restore_rt else &restore;
        ksa = k_sigaction{
            .handler = new.handler.handler,
            .flags = new.flags | SA.RESTORER,
            .mask = undefined,
            .restorer = @ptrCast(restorer_fn),
        };
        @memcpy(@as([*]u8, @ptrCast(&ksa.mask))[0..mask_size], @as([*]const u8, @ptrCast(&new.mask)));
    }

    const ksa_arg = if (act != null) @intFromPtr(&ksa) else 0;
    const oldksa_arg = if (oact != null) @intFromPtr(&oldksa) else 0;

    const result = switch (native_arch) {
        // The sparc version of rt_sigaction needs the restorer function to be passed as an argument too.
        .sparc, .sparc64 => syscall5(.rt_sigaction, sig, ksa_arg, oldksa_arg, @intFromPtr(ksa.restorer), mask_size),
        else => syscall4(.rt_sigaction, sig, ksa_arg, oldksa_arg, mask_size),
    };
    if (E.init(result) != .SUCCESS) return result;

    if (oact) |old| {
        old.handler.handler = oldksa.handler;
        old.flags = @as(c_uint, @truncate(oldksa.flags));
        @memcpy(@as([*]u8, @ptrCast(&old.mask))[0..mask_size], @as([*]const u8, @ptrCast(&oldksa.mask)));
    }

    return 0;
}

pub fn getsockname(fd: i32, noalias addr: *sockaddr, noalias len: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getsockname, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len) });
    }
    return syscall3(.getsockname, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len));
}

pub fn getpeername(fd: i32, noalias addr: *sockaddr, noalias len: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getpeername, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len) });
    }
    return syscall3(.getpeername, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len));
}

pub fn socket(domain: u32, socket_type: u32, protocol: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.socket, &[3]usize{ domain, socket_type, protocol });
    }
    return syscall3(.socket, domain, socket_type, protocol);
}

pub fn setsockopt(fd: i32, level: u32, optname: u32, optval: [*]const u8, optlen: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.setsockopt, &[5]usize{ @as(usize, @bitCast(@as(isize, fd))), level, optname, @intFromPtr(optval), @as(usize, @intCast(optlen)) });
    }
    return syscall5(.setsockopt, @as(usize, @bitCast(@as(isize, fd))), level, optname, @intFromPtr(optval), @as(usize, @intCast(optlen)));
}

pub fn getsockopt(fd: i32, level: u32, optname: u32, noalias optval: [*]u8, noalias optlen: *socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.getsockopt, &[5]usize{ @as(usize, @bitCast(@as(isize, fd))), level, optname, @intFromPtr(optval), @intFromPtr(optlen) });
    }
    return syscall5(.getsockopt, @as(usize, @bitCast(@as(isize, fd))), level, optname, @intFromPtr(optval), @intFromPtr(optlen));
}

pub fn sendmsg(fd: i32, msg: *const msghdr_const, flags: u32) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const msg_usize = @intFromPtr(msg);
    if (native_arch == .x86) {
        return socketcall(SC.sendmsg, &[3]usize{ fd_usize, msg_usize, flags });
    } else {
        return syscall3(.sendmsg, fd_usize, msg_usize, flags);
    }
}

pub fn sendmmsg(fd: i32, msgvec: [*]mmsghdr_const, vlen: u32, flags: u32) usize {
    if (@typeInfo(usize).Int.bits > @typeInfo(@typeInfo(mmsghdr).Struct.fields[1].type).Int.bits) {
        // workaround kernel brokenness:
        // if adding up all iov_len overflows a i32 then split into multiple calls
        // see https://www.openwall.com/lists/musl/2014/06/07/5
        const kvlen = if (vlen > IOV_MAX) IOV_MAX else vlen; // matches kernel
        var next_unsent: usize = 0;
        for (msgvec[0..kvlen], 0..) |*msg, i| {
            var size: i32 = 0;
            const msg_iovlen = @as(usize, @intCast(msg.msg_hdr.msg_iovlen)); // kernel side this is treated as unsigned
            for (msg.msg_hdr.msg_iov[0..msg_iovlen]) |iov| {
                if (iov.iov_len > std.math.maxInt(i32) or @addWithOverflow(size, @as(i32, @intCast(iov.iov_len)))[1] != 0) {
                    // batch-send all messages up to the current message
                    if (next_unsent < i) {
                        const batch_size = i - next_unsent;
                        const r = syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&msgvec[next_unsent]), batch_size, flags);
                        if (E.init(r) != 0) return next_unsent;
                        if (r < batch_size) return next_unsent + r;
                    }
                    // send current message as own packet
                    const r = sendmsg(fd, &msg.msg_hdr, flags);
                    if (E.init(r) != 0) return r;
                    // Linux limits the total bytes sent by sendmsg to INT_MAX, so this cast is safe.
                    msg.msg_len = @as(u32, @intCast(r));
                    next_unsent = i + 1;
                    break;
                }
                size += iov.iov_len;
            }
        }
        if (next_unsent < kvlen or next_unsent == 0) { // want to make sure at least one syscall occurs (e.g. to trigger MSG.EOR)
            const batch_size = kvlen - next_unsent;
            const r = syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&msgvec[next_unsent]), batch_size, flags);
            if (E.init(r) != 0) return r;
            return next_unsent + r;
        }
        return kvlen;
    }
    return syscall4(.sendmmsg, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(msgvec), vlen, flags);
}

pub fn connect(fd: i32, addr: *const anyopaque, len: socklen_t) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const addr_usize = @intFromPtr(addr);
    if (native_arch == .x86) {
        return socketcall(SC.connect, &[3]usize{ fd_usize, addr_usize, len });
    } else {
        return syscall3(.connect, fd_usize, addr_usize, len);
    }
}

pub fn recvmsg(fd: i32, msg: *msghdr, flags: u32) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const msg_usize = @intFromPtr(msg);
    if (native_arch == .x86) {
        return socketcall(SC.recvmsg, &[3]usize{ fd_usize, msg_usize, flags });
    } else {
        return syscall3(.recvmsg, fd_usize, msg_usize, flags);
    }
}

pub fn recvfrom(
    fd: i32,
    noalias buf: [*]u8,
    len: usize,
    flags: u32,
    noalias addr: ?*sockaddr,
    noalias alen: ?*socklen_t,
) usize {
    const fd_usize = @as(usize, @bitCast(@as(isize, fd)));
    const buf_usize = @intFromPtr(buf);
    const addr_usize = @intFromPtr(addr);
    const alen_usize = @intFromPtr(alen);
    if (native_arch == .x86) {
        return socketcall(SC.recvfrom, &[6]usize{ fd_usize, buf_usize, len, flags, addr_usize, alen_usize });
    } else {
        return syscall6(.recvfrom, fd_usize, buf_usize, len, flags, addr_usize, alen_usize);
    }
}

pub fn shutdown(fd: i32, how: i32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.shutdown, &[2]usize{ @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, how))) });
    }
    return syscall2(.shutdown, @as(usize, @bitCast(@as(isize, fd))), @as(usize, @bitCast(@as(isize, how))));
}

pub fn bind(fd: i32, addr: *const sockaddr, len: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.bind, &[3]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @as(usize, @intCast(len)) });
    }
    return syscall3(.bind, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @as(usize, @intCast(len)));
}

pub fn listen(fd: i32, backlog: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.listen, &[2]usize{ @as(usize, @bitCast(@as(isize, fd))), backlog });
    }
    return syscall2(.listen, @as(usize, @bitCast(@as(isize, fd))), backlog);
}

pub fn sendto(fd: i32, buf: [*]const u8, len: usize, flags: u32, addr: ?*const sockaddr, alen: socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.sendto, &[6]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), len, flags, @intFromPtr(addr), @as(usize, @intCast(alen)) });
    }
    return syscall6(.sendto, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(buf), len, flags, @intFromPtr(addr), @as(usize, @intCast(alen)));
}

pub fn sendfile(outfd: i32, infd: i32, offset: ?*i64, count: usize) usize {
    if (@hasField(SYS, "sendfile64")) {
        return syscall4(
            .sendfile64,
            @as(usize, @bitCast(@as(isize, outfd))),
            @as(usize, @bitCast(@as(isize, infd))),
            @intFromPtr(offset),
            count,
        );
    } else {
        return syscall4(
            .sendfile,
            @as(usize, @bitCast(@as(isize, outfd))),
            @as(usize, @bitCast(@as(isize, infd))),
            @intFromPtr(offset),
            count,
        );
    }
}

pub fn socketpair(domain: i32, socket_type: i32, protocol: i32, fd: *[2]i32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.socketpair, &[4]usize{ @as(usize, @intCast(domain)), @as(usize, @intCast(socket_type)), @as(usize, @intCast(protocol)), @intFromPtr(fd) });
    }
    return syscall4(.socketpair, @as(usize, @intCast(domain)), @as(usize, @intCast(socket_type)), @as(usize, @intCast(protocol)), @intFromPtr(fd));
}

pub fn accept(fd: i32, noalias addr: ?*sockaddr, noalias len: ?*socklen_t) usize {
    if (native_arch == .x86) {
        return socketcall(SC.accept, &[4]usize{ fd, addr, len, 0 });
    }
    return accept4(fd, addr, len, 0);
}

pub fn accept4(fd: i32, noalias addr: ?*sockaddr, noalias len: ?*socklen_t, flags: u32) usize {
    if (native_arch == .x86) {
        return socketcall(SC.accept4, &[4]usize{ @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len), flags });
    }
    return syscall4(.accept4, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(addr), @intFromPtr(len), flags);
}

pub fn fstat(fd: i32, stat_buf: *Stat) usize {
    if (@hasField(SYS, "fstat64")) {
        return syscall2(.fstat64, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(stat_buf));
    } else {
        return syscall2(.fstat, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(stat_buf));
    }
}

pub fn stat(pathname: [*:0]const u8, statbuf: *Stat) usize {
    if (@hasField(SYS, "stat64")) {
        return syscall2(.stat64, @intFromPtr(pathname), @intFromPtr(statbuf));
    } else {
        return syscall2(.stat, @intFromPtr(pathname), @intFromPtr(statbuf));
    }
}

pub fn lstat(pathname: [*:0]const u8, statbuf: *Stat) usize {
    if (@hasField(SYS, "lstat64")) {
        return syscall2(.lstat64, @intFromPtr(pathname), @intFromPtr(statbuf));
    } else {
        return syscall2(.lstat, @intFromPtr(pathname), @intFromPtr(statbuf));
    }
}

pub fn fstatat(dirfd: i32, path: [*:0]const u8, stat_buf: *Stat, flags: u32) usize {
    if (@hasField(SYS, "fstatat64")) {
        return syscall4(.fstatat64, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(stat_buf), flags);
    } else {
        return syscall4(.fstatat, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(stat_buf), flags);
    }
}

pub fn statx(dirfd: i32, path: [*:0]const u8, flags: u32, mask: u32, statx_buf: *Statx) usize {
    if (@hasField(SYS, "statx")) {
        return syscall5(
            .statx,
            @as(usize, @bitCast(@as(isize, dirfd))),
            @intFromPtr(path),
            flags,
            mask,
            @intFromPtr(statx_buf),
        );
    }
    return @as(usize, @bitCast(-@as(isize, @intFromEnum(E.NOSYS))));
}

pub fn listxattr(path: [*:0]const u8, list: [*]u8, size: usize) usize {
    return syscall3(.listxattr, @intFromPtr(path), @intFromPtr(list), size);
}

pub fn llistxattr(path: [*:0]const u8, list: [*]u8, size: usize) usize {
    return syscall3(.llistxattr, @intFromPtr(path), @intFromPtr(list), size);
}

pub fn flistxattr(fd: usize, list: [*]u8, size: usize) usize {
    return syscall3(.flistxattr, fd, @intFromPtr(list), size);
}

pub fn getxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.getxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size);
}

pub fn lgetxattr(path: [*:0]const u8, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.lgetxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size);
}

pub fn fgetxattr(fd: usize, name: [*:0]const u8, value: [*]u8, size: usize) usize {
    return syscall4(.lgetxattr, fd, @intFromPtr(name), @intFromPtr(value), size);
}

pub fn setxattr(path: [*:0]const u8, name: [*:0]const u8, value: *const void, size: usize, flags: usize) usize {
    return syscall5(.setxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn lsetxattr(path: [*:0]const u8, name: [*:0]const u8, value: *const void, size: usize, flags: usize) usize {
    return syscall5(.lsetxattr, @intFromPtr(path), @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn fsetxattr(fd: usize, name: [*:0]const u8, value: *const void, size: usize, flags: usize) usize {
    return syscall5(.fsetxattr, fd, @intFromPtr(name), @intFromPtr(value), size, flags);
}

pub fn removexattr(path: [*:0]const u8, name: [*:0]const u8) usize {
    return syscall2(.removexattr, @intFromPtr(path), @intFromPtr(name));
}

pub fn lremovexattr(path: [*:0]const u8, name: [*:0]const u8) usize {
    return syscall2(.lremovexattr, @intFromPtr(path), @intFromPtr(name));
}

pub fn fremovexattr(fd: usize, name: [*:0]const u8) usize {
    return syscall2(.fremovexattr, fd, @intFromPtr(name));
}

pub fn sched_yield() usize {
    return syscall0(.sched_yield);
}

pub fn sched_getaffinity(pid: pid_t, size: usize, set: *cpu_set_t) usize {
    const rc = syscall3(.sched_getaffinity, @as(usize, @bitCast(@as(isize, pid))), size, @intFromPtr(set));
    if (@as(isize, @bitCast(rc)) < 0) return rc;
    if (rc < size) @memset(@as([*]u8, @ptrCast(set))[rc..size], 0);
    return 0;
}

pub fn sched_setaffinity(pid: pid_t, set: *const cpu_set_t) !void {
    const size = @sizeOf(cpu_set_t);
    const rc = syscall3(.sched_setaffinity, @as(usize, @bitCast(@as(isize, pid))), size, @intFromPtr(set));

    switch (std.os.errno(rc)) {
        .SUCCESS => return,
        else => |err| return std.os.unexpectedErrno(err),
    }
}

pub fn epoll_create() usize {
    return epoll_create1(0);
}

pub fn epoll_create1(flags: usize) usize {
    return syscall1(.epoll_create1, flags);
}

pub fn epoll_ctl(epoll_fd: i32, op: u32, fd: i32, ev: ?*epoll_event) usize {
    return syscall4(.epoll_ctl, @as(usize, @bitCast(@as(isize, epoll_fd))), @as(usize, @intCast(op)), @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(ev));
}

pub fn epoll_wait(epoll_fd: i32, events: [*]epoll_event, maxevents: u32, timeout: i32) usize {
    return epoll_pwait(epoll_fd, events, maxevents, timeout, null);
}

pub fn epoll_pwait(epoll_fd: i32, events: [*]epoll_event, maxevents: u32, timeout: i32, sigmask: ?*const sigset_t) usize {
    return syscall6(
        .epoll_pwait,
        @as(usize, @bitCast(@as(isize, epoll_fd))),
        @intFromPtr(events),
        @as(usize, @intCast(maxevents)),
        @as(usize, @bitCast(@as(isize, timeout))),
        @intFromPtr(sigmask),
        @sizeOf(sigset_t),
    );
}

pub fn eventfd(count: u32, flags: u32) usize {
    return syscall2(.eventfd2, count, flags);
}

pub fn timerfd_create(clockid: i32, flags: TFD) usize {
    return syscall2(.timerfd_create, @bitCast(@as(isize, clockid)), @as(u32, @bitCast(flags)));
}

pub fn timerfd_gettime(fd: i32, curr_value: *itimerspec) usize {
    return syscall2(.timerfd_gettime, @bitCast(@as(isize, fd)), @intFromPtr(curr_value));
}

pub fn timerfd_settime(fd: i32, flags: TFD.TIMER, new_value: *const itimerspec, old_value: ?*itimerspec) usize {
    return syscall4(.timerfd_settime, @bitCast(@as(isize, fd)), @as(u32, @bitCast(flags)), @intFromPtr(new_value), @intFromPtr(old_value));
}

pub fn getitimer(which: i32, curr_value: *itimerspec) usize {
    return syscall2(.getitimer, @as(usize, @bitCast(@as(isize, which))), @intFromPtr(curr_value));
}

pub fn setitimer(which: i32, new_value: *const itimerspec, old_value: ?*itimerspec) usize {
    return syscall3(.setitimer, @as(usize, @bitCast(@as(isize, which))), @intFromPtr(new_value), @intFromPtr(old_value));
}

pub fn unshare(flags: usize) usize {
    return syscall1(.unshare, flags);
}

pub fn capget(hdrp: *cap_user_header_t, datap: *cap_user_data_t) usize {
    return syscall2(.capget, @intFromPtr(hdrp), @intFromPtr(datap));
}

pub fn capset(hdrp: *cap_user_header_t, datap: *const cap_user_data_t) usize {
    return syscall2(.capset, @intFromPtr(hdrp), @intFromPtr(datap));
}

pub fn sigaltstack(ss: ?*stack_t, old_ss: ?*stack_t) usize {
    return syscall2(.sigaltstack, @intFromPtr(ss), @intFromPtr(old_ss));
}

pub fn uname(uts: *utsname) usize {
    return syscall1(.uname, @intFromPtr(uts));
}

pub fn io_uring_setup(entries: u32, p: *io_uring_params) usize {
    return syscall2(.io_uring_setup, entries, @intFromPtr(p));
}

pub fn io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32, sig: ?*sigset_t) usize {
    return syscall6(.io_uring_enter, @as(usize, @bitCast(@as(isize, fd))), to_submit, min_complete, flags, @intFromPtr(sig), NSIG / 8);
}

pub fn io_uring_register(fd: i32, opcode: IORING_REGISTER, argument: ?*const anyopaque, nr_args: u32) usize {
    return syscall4(.io_uring_register, @as(usize, @bitCast(@as(isize, fd))), @intFromEnum(opcode), @intFromPtr(argument), nr_args);
}

pub fn memfd_create(name: [*:0]const u8, flags: u32) usize {
    return syscall2(.memfd_create, @intFromPtr(name), flags);
}

pub fn getrusage(who: i32, usage: *rusage) usize {
    return syscall2(.getrusage, @as(usize, @bitCast(@as(isize, who))), @intFromPtr(usage));
}

pub fn tcgetattr(fd: fd_t, termios_p: *termios) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CGETS, @intFromPtr(termios_p));
}

pub fn tcsetattr(fd: fd_t, optional_action: TCSA, termios_p: *const termios) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CSETS + @intFromEnum(optional_action), @intFromPtr(termios_p));
}

pub fn tcgetpgrp(fd: fd_t, pgrp: *pid_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.IOCGPGRP, @intFromPtr(pgrp));
}

pub fn tcsetpgrp(fd: fd_t, pgrp: *const pid_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.IOCSPGRP, @intFromPtr(pgrp));
}

pub fn tcdrain(fd: fd_t) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), T.CSBRK, 1);
}

pub fn ioctl(fd: fd_t, request: u32, argument: usize) usize {
    return syscall3(.ioctl, @as(usize, @bitCast(@as(isize, fd))), request, argument);
}

pub fn signalfd(fd: fd_t, mask: *const sigset_t, flags: u32) usize {
    return syscall4(.signalfd4, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(mask), NSIG / 8, flags);
}

pub fn copy_file_range(fd_in: fd_t, off_in: ?*i64, fd_out: fd_t, off_out: ?*i64, len: usize, flags: u32) usize {
    return syscall6(
        .copy_file_range,
        @as(usize, @bitCast(@as(isize, fd_in))),
        @intFromPtr(off_in),
        @as(usize, @bitCast(@as(isize, fd_out))),
        @intFromPtr(off_out),
        len,
        flags,
    );
}

pub fn bpf(cmd: BPF.Cmd, attr: *BPF.Attr, size: u32) usize {
    return syscall3(.bpf, @intFromEnum(cmd), @intFromPtr(attr), size);
}

pub fn sync() void {
    _ = syscall0(.sync);
}

pub fn syncfs(fd: fd_t) usize {
    return syscall1(.syncfs, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fsync(fd: fd_t) usize {
    return syscall1(.fsync, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn fdatasync(fd: fd_t) usize {
    return syscall1(.fdatasync, @as(usize, @bitCast(@as(isize, fd))));
}

pub fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return syscall5(.prctl, @as(usize, @bitCast(@as(isize, option))), arg2, arg3, arg4, arg5);
}

pub fn getrlimit(resource: rlimit_resource, rlim: *rlimit) usize {
    // use prlimit64 to have 64 bit limits on 32 bit platforms
    return prlimit(0, resource, null, rlim);
}

pub fn setrlimit(resource: rlimit_resource, rlim: *const rlimit) usize {
    // use prlimit64 to have 64 bit limits on 32 bit platforms
    return prlimit(0, resource, rlim, null);
}

pub fn prlimit(pid: pid_t, resource: rlimit_resource, new_limit: ?*const rlimit, old_limit: ?*rlimit) usize {
    return syscall4(
        .prlimit64,
        @as(usize, @bitCast(@as(isize, pid))),
        @as(usize, @bitCast(@as(isize, @intFromEnum(resource)))),
        @intFromPtr(new_limit),
        @intFromPtr(old_limit),
    );
}

pub fn mincore(address: [*]u8, len: usize, vec: [*]u8) usize {
    return syscall3(.mincore, @intFromPtr(address), len, @intFromPtr(vec));
}

pub fn madvise(address: [*]u8, len: usize, advice: u32) usize {
    return syscall3(.madvise, @intFromPtr(address), len, advice);
}

pub fn pidfd_open(pid: pid_t, flags: u32) usize {
    return syscall2(.pidfd_open, @as(usize, @bitCast(@as(isize, pid))), flags);
}

pub fn pidfd_getfd(pidfd: fd_t, targetfd: fd_t, flags: u32) usize {
    return syscall3(
        .pidfd_getfd,
        @as(usize, @bitCast(@as(isize, pidfd))),
        @as(usize, @bitCast(@as(isize, targetfd))),
        flags,
    );
}

pub fn pidfd_send_signal(pidfd: fd_t, sig: i32, info: ?*siginfo_t, flags: u32) usize {
    return syscall4(
        .pidfd_send_signal,
        @as(usize, @bitCast(@as(isize, pidfd))),
        @as(usize, @bitCast(@as(isize, sig))),
        @intFromPtr(info),
        flags,
    );
}

pub fn process_vm_readv(pid: pid_t, local: []iovec, remote: []const iovec_const, flags: usize) usize {
    return syscall6(
        .process_vm_readv,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(local.ptr),
        local.len,
        @intFromPtr(remote.ptr),
        remote.len,
        flags,
    );
}

pub fn process_vm_writev(pid: pid_t, local: []const iovec_const, remote: []const iovec_const, flags: usize) usize {
    return syscall6(
        .process_vm_writev,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(local.ptr),
        local.len,
        @intFromPtr(remote.ptr),
        remote.len,
        flags,
    );
}

pub fn fadvise(fd: fd_t, offset: i64, len: i64, advice: usize) usize {
    if (comptime builtin.cpu.arch.isMIPS()) {
        // MIPS requires a 7 argument syscall

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall7(
            .fadvise64,
            @as(usize, @bitCast(@as(isize, fd))),
            0,
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
            advice,
        );
    } else if (comptime builtin.cpu.arch.isARM()) {
        // ARM reorders the arguments

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall6(
            .fadvise64_64,
            @as(usize, @bitCast(@as(isize, fd))),
            advice,
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
        );
    } else if (@hasField(SYS, "fadvise64_64") and usize_bits != 64) {
        // The extra usize check is needed to avoid SPARC64 because it provides both
        // fadvise64 and fadvise64_64 but the latter behaves differently than other platforms.

        const offset_halves = splitValue64(offset);
        const length_halves = splitValue64(len);

        return syscall6(
            .fadvise64_64,
            @as(usize, @bitCast(@as(isize, fd))),
            offset_halves[0],
            offset_halves[1],
            length_halves[0],
            length_halves[1],
            advice,
        );
    } else {
        return syscall4(
            .fadvise64,
            @as(usize, @bitCast(@as(isize, fd))),
            @as(usize, @bitCast(offset)),
            @as(usize, @bitCast(len)),
            advice,
        );
    }
}

pub fn perf_event_open(
    attr: *perf_event_attr,
    pid: pid_t,
    cpu: i32,
    group_fd: fd_t,
    flags: usize,
) usize {
    return syscall5(
        .perf_event_open,
        @intFromPtr(attr),
        @as(usize, @bitCast(@as(isize, pid))),
        @as(usize, @bitCast(@as(isize, cpu))),
        @as(usize, @bitCast(@as(isize, group_fd))),
        flags,
    );
}

pub fn seccomp(operation: u32, flags: u32, args: ?*const anyopaque) usize {
    return syscall3(.seccomp, operation, flags, @intFromPtr(args));
}

pub fn ptrace(
    req: u32,
    pid: pid_t,
    addr: usize,
    data: usize,
    addr2: usize,
) usize {
    return syscall5(
        .ptrace,
        req,
        @as(usize, @bitCast(@as(isize, pid))),
        addr,
        data,
        addr2,
    );
}

/// Query the page cache statistics of a file.
pub fn cachestat(
    /// The open file descriptor to retrieve statistics from.
    fd: fd_t,
    /// The byte range in `fd` to query.
    /// When `len > 0`, the range is `[off..off + len]`.
    /// When `len` == 0, the range is from `off` to the end of `fd`.
    cstat_range: *const cache_stat_range,
    /// The structure where page cache statistics are stored.
    cstat: *cache_stat,
    /// Currently unused, and must be set to `0`.
    flags: u32,
) usize {
    return syscall4(
        .cachestat,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(cstat_range),
        @intFromPtr(cstat),
        flags,
    );
}

pub fn map_shadow_stack(addr: u64, size: u64, flags: u32) usize {
    return syscall3(.map_shadow_stack, addr, size, flags);
}

const std = @import("../../std.zig");
const fd_t = std.os.linux.fd_t;
const ReturnCode = std.os.linux.ReturnCode;
const SYS = std.os.linux.SYS;

pub fn arg(x: anytype) usize {
    return switch (@typeInfo(@TypeOf(x))) {
        .ComptimeInt => x,
        .Int => |info| switch (info.signedness) {
            .unsigned => x,
            .signed => @bitCast(@as(isize, x)),
        },
        .Pointer => @intFromPtr(x),
        else => @compileError("invalid syscall argument type"),
    };
}

