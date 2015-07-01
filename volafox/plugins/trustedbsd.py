import sys
import struct

from tableprint import columnprint

# 32bit, 64bit
MAC_POLICY_LIST_STRUCTURE = [[28, '=IIIIIII'], [32, '=IIIIIIQ']]
MAC_POLICY_CONF_STRUCTURE = [[40, '=IIIIIIIIII'], [80, '=QQQQQQQQQQ']]

# 32bit, 64bit
Pointer_Structure = [[4, '=I'], [8, '=Q']]

# http://www.opensource.apple.com/source/xnu/xnu-1504.15.3/security/mac_policy.h Version 2
ops_func_pointer_sl = ['mpo_audit_check_postselect',  'mpo_audit_check_preselect',  'mpo_bpfdesc_label_associate',  'mpo_bpfdesc_label_destroy',  'mpo_bpfdesc_label_init',  'mpo_bpfdesc_check_receive',  'mpo_cred_check_label_update_execve',  'mpo_cred_check_label_update',  'mpo_cred_check_visible',  'mpo_cred_label_associate_fork',  'mpo_cred_label_associate_kernel',  'mpo_cred_label_associate',  'mpo_cred_label_associate_user',  'mpo_cred_label_destroy',  'mpo_cred_label_externalize_audit',  'mpo_cred_label_externalize',  'mpo_cred_label_init',  'mpo_cred_label_internalize',  'mpo_cred_label_update_execve',  'mpo_cred_label_update',  'mpo_devfs_label_associate_device',  'mpo_devfs_label_associate_directory',  'mpo_devfs_label_copy',  'mpo_devfs_label_destroy',  'mpo_devfs_label_init',  'mpo_devfs_label_update',  'mpo_file_check_change_offset',  'mpo_file_check_create',  'mpo_file_check_dup',  'mpo_file_check_fcntl',  'mpo_file_check_get_offset',  'mpo_file_check_get',  'mpo_file_check_inherit',  'mpo_file_check_ioctl',  'mpo_file_check_lock',  'mpo_file_check_mmap_downgrade',  'mpo_file_check_mmap',  'mpo_file_check_receive',  'mpo_file_check_set',  'mpo_file_label_init',  'mpo_file_label_destroy',  'mpo_file_label_associate',  'mpo_ifnet_check_label_update',  'mpo_ifnet_check_transmit',  'mpo_ifnet_label_associate',  'mpo_ifnet_label_copy',  'mpo_ifnet_label_destroy',  'mpo_ifnet_label_externalize',  'mpo_ifnet_label_init',  'mpo_ifnet_label_internalize',  'mpo_ifnet_label_update',  'mpo_ifnet_label_recycle',  'mpo_inpcb_check_deliver',  'mpo_inpcb_label_associate',  'mpo_inpcb_label_destroy',  'mpo_inpcb_label_init',  'mpo_inpcb_label_recycle',  'mpo_inpcb_label_update',  'mpo_iokit_check_device',  'mpo_ipq_label_associate',  'mpo_ipq_label_compare',  'mpo_ipq_label_destroy',  'mpo_ipq_label_init',  'mpo_ipq_label_update',  'mpo_lctx_check_label_update',  'mpo_lctx_label_destroy',  'mpo_lctx_label_externalize',  'mpo_lctx_label_init',  'mpo_lctx_label_internalize',  'mpo_lctx_label_update',  'mpo_lctx_notify_create',  'mpo_lctx_notify_join',  'mpo_lctx_notify_leave',  'mpo_mbuf_label_associate_bpfdesc',  'mpo_mbuf_label_associate_ifnet',  'mpo_mbuf_label_associate_inpcb',  'mpo_mbuf_label_associate_ipq',  'mpo_mbuf_label_associate_linklayer',  'mpo_mbuf_label_associate_multicast_encap',  'mpo_mbuf_label_associate_netlayer',  'mpo_mbuf_label_associate_socket',  'mpo_mbuf_label_copy',  'mpo_mbuf_label_destroy',  'mpo_mbuf_label_init',  'mpo_mount_check_fsctl',  'mpo_mount_check_getattr',  'mpo_mount_check_label_update',  'mpo_mount_check_mount',  'mpo_mount_check_remount',  'mpo_mount_check_setattr',  'mpo_mount_check_stat',  'mpo_mount_check_umount',  'mpo_mount_label_associate',  'mpo_mount_label_destroy',  'mpo_mount_label_externalize',  'mpo_mount_label_init',  'mpo_mount_label_internalize',  'mpo_netinet_fragment',  'mpo_netinet_icmp_reply',  'mpo_netinet_tcp_reply',  'mpo_pipe_check_ioctl',  'mpo_pipe_check_kqfilter',  'mpo_pipe_check_label_update',  'mpo_pipe_check_read',  'mpo_pipe_check_select',  'mpo_pipe_check_stat',  'mpo_pipe_check_write',  'mpo_pipe_label_associate',  'mpo_pipe_label_copy',  'mpo_pipe_label_destroy',  'mpo_pipe_label_externalize',  'mpo_pipe_label_init',  'mpo_pipe_label_internalize',  'mpo_pipe_label_update',  'mpo_policy_destroy',  'mpo_policy_init',  'mpo_policy_initbsd',  'mpo_policy_syscall',  'mpo_port_check_copy_send',  'mpo_port_check_hold_receive',  'mpo_port_check_hold_send_once',  'mpo_port_check_hold_send',  'mpo_port_check_label_update',  'mpo_port_check_make_send_once',  'mpo_port_check_make_send',  'mpo_port_check_method',  'mpo_port_check_move_receive',  'mpo_port_check_move_send_once',  'mpo_port_check_move_send',  'mpo_port_check_receive',  'mpo_port_check_send',  'mpo_port_check_service',  'mpo_port_label_associate_kernel',  'mpo_port_label_associate',  'mpo_port_label_compute',  'mpo_port_label_copy',  'mpo_port_label_destroy',  'mpo_port_label_init',  'mpo_port_label_update_cred',  'mpo_port_label_update_kobject',  'mpo_posixsem_check_create',  'mpo_posixsem_check_open',  'mpo_posixsem_check_post',  'mpo_posixsem_check_unlink',  'mpo_posixsem_check_wait',  'mpo_posixsem_label_associate',  'mpo_posixsem_label_destroy',  'mpo_posixsem_label_init',  'mpo_posixshm_check_create',  'mpo_posixshm_check_mmap',  'mpo_posixshm_check_open',  'mpo_posixshm_check_stat',  'mpo_posixshm_check_truncate',  'mpo_posixshm_check_unlink',  'mpo_posixshm_label_associate',  'mpo_posixshm_label_destroy',  'mpo_posixshm_label_init',  'mpo_proc_check_debug',  'mpo_proc_check_fork',  'mpo_proc_check_get_task_name',  'mpo_proc_check_get_task',  'mpo_proc_check_getaudit',  'mpo_proc_check_getauid',  'mpo_proc_check_getlcid',  'mpo_proc_check_mprotect',  'mpo_proc_check_sched',  'mpo_proc_check_setaudit',  'mpo_proc_check_setauid',  'mpo_proc_check_setlcid',  'mpo_proc_check_signal',  'mpo_proc_check_wait',  'mpo_proc_label_destroy',  'mpo_proc_label_init',  'mpo_socket_check_accept',  'mpo_socket_check_accepted',  'mpo_socket_check_bind',  'mpo_socket_check_connect',  'mpo_socket_check_create',  'mpo_socket_check_deliver',  'mpo_socket_check_kqfilter',  'mpo_socket_check_label_update',  'mpo_socket_check_listen',  'mpo_socket_check_receive',  'mpo_socket_check_received',  'mpo_socket_check_select',  'mpo_socket_check_send',  'mpo_socket_check_stat',  'mpo_socket_check_setsockopt',  'mpo_socket_check_getsockopt',  'mpo_socket_label_associate_accept',  'mpo_socket_label_associate',  'mpo_socket_label_copy',  'mpo_socket_label_destroy',  'mpo_socket_label_externalize',  'mpo_socket_label_init',  'mpo_socket_label_internalize',  'mpo_socket_label_update',  'mpo_socketpeer_label_associate_mbuf',  'mpo_socketpeer_label_associate_socket',  'mpo_socketpeer_label_destroy',  'mpo_socketpeer_label_externalize',  'mpo_socketpeer_label_init',  'mpo_system_check_acct',  'mpo_system_check_audit',  'mpo_system_check_auditctl',  'mpo_system_check_auditon',  'mpo_system_check_host_priv',  'mpo_system_check_nfsd',  'mpo_system_check_reboot',  'mpo_system_check_settime',  'mpo_system_check_swapoff',  'mpo_system_check_swapon',  'mpo_system_check_sysctl',  'mpo_sysvmsg_label_associate',  'mpo_sysvmsg_label_destroy',  'mpo_sysvmsg_label_init',  'mpo_sysvmsg_label_recycle',  'mpo_sysvmsq_check_enqueue',  'mpo_sysvmsq_check_msgrcv',  'mpo_sysvmsq_check_msgrmid',  'mpo_sysvmsq_check_msqctl',  'mpo_sysvmsq_check_msqget',  'mpo_sysvmsq_check_msqrcv',  'mpo_sysvmsq_check_msqsnd',  'mpo_sysvmsq_label_associate',  'mpo_sysvmsq_label_destroy',  'mpo_sysvmsq_label_init',  'mpo_sysvmsq_label_recycle',  'mpo_sysvsem_check_semctl',  'mpo_sysvsem_check_semget',  'mpo_sysvsem_check_semop',  'mpo_sysvsem_label_associate',  'mpo_sysvsem_label_destroy',  'mpo_sysvsem_label_init',  'mpo_sysvsem_label_recycle',  'mpo_sysvshm_check_shmat',  'mpo_sysvshm_check_shmctl',  'mpo_sysvshm_check_shmdt',  'mpo_sysvshm_check_shmget',  'mpo_sysvshm_label_associate',  'mpo_sysvshm_label_destroy',  'mpo_sysvshm_label_init',  'mpo_sysvshm_label_recycle',  'mpo_task_label_associate_kernel',  'mpo_task_label_associate',  'mpo_task_label_copy',  'mpo_task_label_destroy',  'mpo_task_label_externalize',  'mpo_task_label_init',  'mpo_task_label_internalize',  'mpo_task_label_update',  'mpo_thread_userret',  'mpo_vnode_check_access',  'mpo_vnode_check_chdir',  'mpo_vnode_check_chroot',  'mpo_vnode_check_create',  'mpo_vnode_check_deleteextattr',  'mpo_vnode_check_exchangedata',  'mpo_vnode_check_exec',  'mpo_vnode_check_getattrlist',  'mpo_vnode_check_getextattr',  'mpo_vnode_check_ioctl',  'mpo_vnode_check_kqfilter',  'mpo_vnode_check_label_update',  'mpo_vnode_check_link',  'mpo_vnode_check_listextattr',  'mpo_vnode_check_lookup',  'mpo_vnode_check_open',  'mpo_vnode_check_read',  'mpo_vnode_check_readdir',  'mpo_vnode_check_readlink',  'mpo_vnode_check_rename_from',  'mpo_vnode_check_rename_to',  'mpo_vnode_check_revoke',  'mpo_vnode_check_select',  'mpo_vnode_check_setattrlist',  'mpo_vnode_check_setextattr',  'mpo_vnode_check_setflags',  'mpo_vnode_check_setmode',  'mpo_vnode_check_setowner',  'mpo_vnode_check_setutimes',  'mpo_vnode_check_stat',  'mpo_vnode_check_truncate',  'mpo_vnode_check_unlink',  'mpo_vnode_check_write',  'mpo_vnode_label_associate_devfs',  'mpo_vnode_label_associate_extattr',  'mpo_vnode_label_associate_file',  'mpo_vnode_label_associate_pipe',  'mpo_vnode_label_associate_posixsem',  'mpo_vnode_label_associate_posixshm',  'mpo_vnode_label_associate_singlelabel',  'mpo_vnode_label_associate_socket',  'mpo_vnode_label_copy',  'mpo_vnode_label_destroy',  'mpo_vnode_label_externalize_audit',  'mpo_vnode_label_externalize',  'mpo_vnode_label_init',  'mpo_vnode_label_internalize',  'mpo_vnode_label_recycle',  'mpo_vnode_label_store',  'mpo_vnode_label_update_extattr',  'mpo_vnode_label_update',  'mpo_vnode_notify_create',  'mpo_vnode_check_signature',  'mpo_vnode_check_uipc_bind',  'mpo_vnode_check_uipc_connect',  'mpo_proc_check_run_cs_invalid',  'mpo_proc_check_suspend_resume',  'mpo_reserved5',  'mpo_reserved6',  'mpo_reserved7',  'mpo_reserved8',  'mpo_reserved9']

# http://www.opensource.apple.com/source/xnu/xnu-1699.22.73/security/mac_policy.h Version 3
ops_func_pointer_lion = ['mpo_audit_check_postselect',  'mpo_audit_check_preselect',  'mpo_bpfdesc_label_associate',  'mpo_bpfdesc_label_destroy',  'mpo_bpfdesc_label_init',  'mpo_bpfdesc_check_receive',  'mpo_cred_check_label_update_execve',  'mpo_cred_check_label_update',  'mpo_cred_check_visible',  'mpo_cred_label_associate_fork',  'mpo_cred_label_associate_kernel',  'mpo_cred_label_associate',  'mpo_cred_label_associate_user',  'mpo_cred_label_destroy',  'mpo_cred_label_externalize_audit',  'mpo_cred_label_externalize',  'mpo_cred_label_init',  'mpo_cred_label_internalize',  'mpo_cred_label_update_execve',  'mpo_cred_label_update',  'mpo_devfs_label_associate_device',  'mpo_devfs_label_associate_directory',  'mpo_devfs_label_copy',  'mpo_devfs_label_destroy',  'mpo_devfs_label_init',  'mpo_devfs_label_update',  'mpo_file_check_change_offset',  'mpo_file_check_create',  'mpo_file_check_dup',  'mpo_file_check_fcntl',  'mpo_file_check_get_offset',  'mpo_file_check_get',  'mpo_file_check_inherit',  'mpo_file_check_ioctl',  'mpo_file_check_lock',  'mpo_file_check_mmap_downgrade',  'mpo_file_check_mmap',  'mpo_file_check_receive',  'mpo_file_check_set',  'mpo_file_label_init',  'mpo_file_label_destroy',  'mpo_file_label_associate',  'mpo_ifnet_check_label_update',  'mpo_ifnet_check_transmit',  'mpo_ifnet_label_associate',  'mpo_ifnet_label_copy',  'mpo_ifnet_label_destroy',  'mpo_ifnet_label_externalize',  'mpo_ifnet_label_init',  'mpo_ifnet_label_internalize',  'mpo_ifnet_label_update',  'mpo_ifnet_label_recycle',  'mpo_inpcb_check_deliver',  'mpo_inpcb_label_associate',  'mpo_inpcb_label_destroy',  'mpo_inpcb_label_init',  'mpo_inpcb_label_recycle',  'mpo_inpcb_label_update',  'mpo_iokit_check_device',  'mpo_ipq_label_associate',  'mpo_ipq_label_compare',  'mpo_ipq_label_destroy',  'mpo_ipq_label_init',  'mpo_ipq_label_update',  'mpo_lctx_check_label_update',  'mpo_lctx_label_destroy',  'mpo_lctx_label_externalize',  'mpo_lctx_label_init',  'mpo_lctx_label_internalize',  'mpo_lctx_label_update',  'mpo_lctx_notify_create',  'mpo_lctx_notify_join',  'mpo_lctx_notify_leave',  'mpo_mbuf_label_associate_bpfdesc',  'mpo_mbuf_label_associate_ifnet',  'mpo_mbuf_label_associate_inpcb',  'mpo_mbuf_label_associate_ipq',  'mpo_mbuf_label_associate_linklayer',  'mpo_mbuf_label_associate_multicast_encap',  'mpo_mbuf_label_associate_netlayer',  'mpo_mbuf_label_associate_socket',  'mpo_mbuf_label_copy',  'mpo_mbuf_label_destroy',  'mpo_mbuf_label_init',  'mpo_mount_check_fsctl',  'mpo_mount_check_getattr',  'mpo_mount_check_label_update',  'mpo_mount_check_mount',  'mpo_mount_check_remount',  'mpo_mount_check_setattr',  'mpo_mount_check_stat',  'mpo_mount_check_umount',  'mpo_mount_label_associate',  'mpo_mount_label_destroy',  'mpo_mount_label_externalize',  'mpo_mount_label_init',  'mpo_mount_label_internalize',  'mpo_netinet_fragment',  'mpo_netinet_icmp_reply',  'mpo_netinet_tcp_reply',  'mpo_pipe_check_ioctl',  'mpo_pipe_check_kqfilter',  'mpo_pipe_check_label_update',  'mpo_pipe_check_read',  'mpo_pipe_check_select',  'mpo_pipe_check_stat',  'mpo_pipe_check_write',  'mpo_pipe_label_associate',  'mpo_pipe_label_copy',  'mpo_pipe_label_destroy',  'mpo_pipe_label_externalize',  'mpo_pipe_label_init',  'mpo_pipe_label_internalize',  'mpo_pipe_label_update',  'mpo_policy_destroy',  'mpo_policy_init',  'mpo_policy_initbsd',  'mpo_policy_syscall',  'mpo_port_check_copy_send',  'mpo_port_check_hold_receive',  'mpo_port_check_hold_send_once',  'mpo_port_check_hold_send',  'mpo_port_check_label_update',  'mpo_port_check_make_send_once',  'mpo_port_check_make_send',  'mpo_port_check_method',  'mpo_port_check_move_receive',  'mpo_port_check_move_send_once',  'mpo_port_check_move_send',  'mpo_port_check_receive',  'mpo_port_check_send',  'mpo_port_check_service',  'mpo_port_label_associate_kernel',  'mpo_port_label_associate',  'mpo_port_label_compute',  'mpo_port_label_copy',  'mpo_port_label_destroy',  'mpo_port_label_init',  'mpo_port_label_update_cred',  'mpo_port_label_update_kobject',  'mpo_posixsem_check_create',  'mpo_posixsem_check_open',  'mpo_posixsem_check_post',  'mpo_posixsem_check_unlink',  'mpo_posixsem_check_wait',  'mpo_posixsem_label_associate',  'mpo_posixsem_label_destroy',  'mpo_posixsem_label_init',  'mpo_posixshm_check_create',  'mpo_posixshm_check_mmap',  'mpo_posixshm_check_open',  'mpo_posixshm_check_stat',  'mpo_posixshm_check_truncate',  'mpo_posixshm_check_unlink',  'mpo_posixshm_label_associate',  'mpo_posixshm_label_destroy',  'mpo_posixshm_label_init',  'mpo_proc_check_debug',  'mpo_proc_check_fork',  'mpo_proc_check_get_task_name',  'mpo_proc_check_get_task',  'mpo_proc_check_getaudit',  'mpo_proc_check_getauid',  'mpo_proc_check_getlcid',  'mpo_proc_check_mprotect',  'mpo_proc_check_sched',  'mpo_proc_check_setaudit',  'mpo_proc_check_setauid',  'mpo_proc_check_setlcid',  'mpo_proc_check_signal',  'mpo_proc_check_wait',  'mpo_proc_label_destroy',  'mpo_proc_label_init',  'mpo_socket_check_accept',  'mpo_socket_check_accepted',  'mpo_socket_check_bind',  'mpo_socket_check_connect',  'mpo_socket_check_create',  'mpo_socket_check_deliver',  'mpo_socket_check_kqfilter',  'mpo_socket_check_label_update',  'mpo_socket_check_listen',  'mpo_socket_check_receive',  'mpo_socket_check_received',  'mpo_socket_check_select',  'mpo_socket_check_send',  'mpo_socket_check_stat',  'mpo_socket_check_setsockopt',  'mpo_socket_check_getsockopt',  'mpo_socket_label_associate_accept',  'mpo_socket_label_associate',  'mpo_socket_label_copy',  'mpo_socket_label_destroy',  'mpo_socket_label_externalize',  'mpo_socket_label_init',  'mpo_socket_label_internalize',  'mpo_socket_label_update',  'mpo_socketpeer_label_associate_mbuf',  'mpo_socketpeer_label_associate_socket',  'mpo_socketpeer_label_destroy',  'mpo_socketpeer_label_externalize',  'mpo_socketpeer_label_init',  'mpo_system_check_acct',  'mpo_system_check_audit',  'mpo_system_check_auditctl',  'mpo_system_check_auditon',  'mpo_system_check_host_priv',  'mpo_system_check_nfsd',  'mpo_system_check_reboot',  'mpo_system_check_settime',  'mpo_system_check_swapoff',  'mpo_system_check_swapon',  'mpo_system_check_sysctl',  'mpo_sysvmsg_label_associate',  'mpo_sysvmsg_label_destroy',  'mpo_sysvmsg_label_init',  'mpo_sysvmsg_label_recycle',  'mpo_sysvmsq_check_enqueue',  'mpo_sysvmsq_check_msgrcv',  'mpo_sysvmsq_check_msgrmid',  'mpo_sysvmsq_check_msqctl',  'mpo_sysvmsq_check_msqget',  'mpo_sysvmsq_check_msqrcv',  'mpo_sysvmsq_check_msqsnd',  'mpo_sysvmsq_label_associate',  'mpo_sysvmsq_label_destroy',  'mpo_sysvmsq_label_init',  'mpo_sysvmsq_label_recycle',  'mpo_sysvsem_check_semctl',  'mpo_sysvsem_check_semget',  'mpo_sysvsem_check_semop',  'mpo_sysvsem_label_associate',  'mpo_sysvsem_label_destroy',  'mpo_sysvsem_label_init',  'mpo_sysvsem_label_recycle',  'mpo_sysvshm_check_shmat',  'mpo_sysvshm_check_shmctl',  'mpo_sysvshm_check_shmdt',  'mpo_sysvshm_check_shmget',  'mpo_sysvshm_label_associate',  'mpo_sysvshm_label_destroy',  'mpo_sysvshm_label_init',  'mpo_sysvshm_label_recycle',  'mpo_task_label_associate_kernel',  'mpo_task_label_associate',  'mpo_task_label_copy',  'mpo_task_label_destroy',  'mpo_task_label_externalize',  'mpo_task_label_init',  'mpo_task_label_internalize',  'mpo_task_label_update',  'mpo_iokit_check_hid_control',  'mpo_vnode_check_access',  'mpo_vnode_check_chdir',  'mpo_vnode_check_chroot',  'mpo_vnode_check_create',  'mpo_vnode_check_deleteextattr',  'mpo_vnode_check_exchangedata',  'mpo_vnode_check_exec',  'mpo_vnode_check_getattrlist',  'mpo_vnode_check_getextattr',  'mpo_vnode_check_ioctl',  'mpo_vnode_check_kqfilter',  'mpo_vnode_check_label_update',  'mpo_vnode_check_link',  'mpo_vnode_check_listextattr',  'mpo_vnode_check_lookup',  'mpo_vnode_check_open',  'mpo_vnode_check_read',  'mpo_vnode_check_readdir',  'mpo_vnode_check_readlink',  'mpo_vnode_check_rename_from',  'mpo_vnode_check_rename_to',  'mpo_vnode_check_revoke',  'mpo_vnode_check_select',  'mpo_vnode_check_setattrlist',  'mpo_vnode_check_setextattr',  'mpo_vnode_check_setflags',  'mpo_vnode_check_setmode',  'mpo_vnode_check_setowner',  'mpo_vnode_check_setutimes',  'mpo_vnode_check_stat',  'mpo_vnode_check_truncate',  'mpo_vnode_check_unlink',  'mpo_vnode_check_write',  'mpo_vnode_label_associate_devfs',  'mpo_vnode_label_associate_extattr',  'mpo_vnode_label_associate_file',  'mpo_vnode_label_associate_pipe',  'mpo_vnode_label_associate_posixsem',  'mpo_vnode_label_associate_posixshm',  'mpo_vnode_label_associate_singlelabel',  'mpo_vnode_label_associate_socket',  'mpo_vnode_label_copy',  'mpo_vnode_label_destroy',  'mpo_vnode_label_externalize_audit',  'mpo_vnode_label_externalize',  'mpo_vnode_label_init',  'mpo_vnode_label_internalize',  'mpo_vnode_label_recycle',  'mpo_vnode_label_store',  'mpo_vnode_label_update_extattr',  'mpo_vnode_label_update',  'mpo_vnode_notify_create',  'mpo_vnode_check_signature',  'mpo_vnode_check_uipc_bind',  'mpo_vnode_check_uipc_connect',  'mpo_proc_check_run_cs_invalid',  'mpo_proc_check_suspend_resume',  'mpo_thread_userret',  'mpo_iokit_check_set_properties',  'mpo_system_check_chud',  'mpo_vnode_check_searchfs',  'mpo_priv_check',  'mpo_priv_grant',  'mpo_proc_check_map_anon',  'mpo_vnode_check_fsgetpath',  'mpo_iokit_check_open',  'mpo_proc_check_ledger',  'mpo_vnode_notify_rename',  'mpo_thread_label_init',  'mpo_thread_label_destroy',  'mpo_system_check_kas_info',  'mpo_reserved18',  'mpo_reserved19',  'mpo_reserved20',  'mpo_reserved21',  'mpo_reserved22',  'mpo_reserved23',  'mpo_reserved24',  'mpo_reserved25',  'mpo_reserved26',  'mpo_reserved27',  'mpo_reserved28',  'mpo_reserved29']

class trustedbsd():
    def __init__(self, x86_mem_pae, arch, build, base_address, os_version):
        self.x86_mem_pae = x86_mem_pae
        self.arch = arch
        self.build = build
        self.base_address = base_address
        self.osversion = os_version


# base code : http://www.opensource.apple.com/source/xnu/xnu-1699.24.23/security/mac_internal.h

    def get_mac_policy_list(self, sym_addr): # 11.11.23 64bit suppport
        policy_list = []

        #print 'base: %x'%self.x86_mem_pae.vtop(sym_addr+self.base_address)

        if not(self.x86_mem_pae.is_valid_address(sym_addr+self.base_address)):
            return policy_list
        
        if self.arch == 32:
            MAC_POLICY_LIST = MAC_POLICY_LIST_STRUCTURE[0]
            Pointer = Pointer_Structure[0]
            MAC_POLICY_CONF = MAC_POLICY_CONF_STRUCTURE[0]
        elif self.arch == 64:
            MAC_POLICY_LIST = MAC_POLICY_LIST_STRUCTURE[1]
            Pointer = Pointer_Structure[1]
            MAC_POLICY_CONF = MAC_POLICY_CONF_STRUCTURE[1]


# struct mac_policy_list {
#     u_int               numloaded;
#     u_int               max;
#     u_int               maxindex;
#     u_int               staticmax;
#     u_int               chunks;
#     u_int               freehint;
#     struct mac_policy_list_element  *entries;
# };

        mac_policy_ptr = self.x86_mem_pae.read(sym_addr+self.base_address, MAC_POLICY_LIST[0])
        mac_policy_structure = struct.unpack(MAC_POLICY_LIST[1], mac_policy_ptr)

        #print 'numloaded : %d'%mac_policy_structure[0]
        #print 'max : %d'%mac_policy_structure[1]
        #print 'max index : %d'%mac_policy_structure[2]
        #print 'static index : %d'%mac_policy_structure[3]
        #print 'chunks : %d'%mac_policy_structure[4]
        #print 'freehint : %d'%mac_policy_structure[5]
        #print '*entries: %x'%self.x86_mem_pae.vtop(mac_policy_structure[6])


        mac_policy_list = []

        count = 0
        for offset in range(0, mac_policy_structure[1]): # max count
            mac_policy_list_element_ptr = self.x86_mem_pae.read(mac_policy_structure[6]+(offset*Pointer[0]), Pointer[0])
            mac_policy_conf = struct.unpack(Pointer[1], mac_policy_list_element_ptr)[0]

            if mac_policy_conf == 0:
                continue
            count = count + 1
            mac_policy_list.append(mac_policy_conf)
            #print '%x'%self.x86_mem_pae.vtop(mac_policy_conf)

        mac_policy_structure = [mac_policy_structure[0], mac_policy_structure[1], count]

        # if count != mac_policy_structure[0]: # numloaded
        #     print '[+] invalid loaded policy count'

# http://opensource.apple.com/source/xnu/xnu-2050.18.24/security/mac_policy.h
# /**
#   @brief Mac policy configuration

#   This structure specifies the configuration information for a
#   MAC policy module.  A policy module developer must supply
#   a short unique policy name, a more descriptive full name, a list of label
#   namespaces and count, a pointer to the registered enty point operations,
#   any load time flags, and optionally, a pointer to a label slot identifier.

#   The Framework will update the runtime flags (mpc_runtime_flags) to
#   indicate that the module has been registered.

#   If the label slot identifier (mpc_field_off) is NULL, the Framework
#   will not provide label storage for the policy.  Otherwise, the
#   Framework will store the label location (slot) in this field.

#   The mpc_list field is used by the Framework and should not be
#   modified by policies.
# */
# /* XXX - reorder these for better aligment on 64bit platforms */
# struct mac_policy_conf {
#     const char      *mpc_name;      /** policy name */
#     const char      *mpc_fullname;      /** full name */
#     const char      **mpc_labelnames;   /** managed label namespaces */
#     unsigned int         mpc_labelname_count;   /** number of managed label namespaces */
#     struct mac_policy_ops   *mpc_ops;       /** operation vector */
#     int          mpc_loadtime_flags;    /** load time flags */
#     int         *mpc_field_off;     /** label slot */
#     int          mpc_runtime_flags; /** run time flags */
#     mpc_t            mpc_list;      /** List reference */
#     void            *mpc_data;      /** module data */
# };


        for offset in range(0, len(mac_policy_list)):
            mac_conf_data = []

            mac_conf_ptr = self.x86_mem_pae.read(mac_policy_list[offset], MAC_POLICY_CONF[0])
            mac_conf = struct.unpack(MAC_POLICY_CONF[1], mac_conf_ptr)

            count = 0
            mpc_name = ''
            while 1:
                byte = struct.unpack('=c', self.x86_mem_pae.read(mac_conf[0] + count, 1))[0]
                if byte == '\x00':
                    break
                mpc_name = mpc_name + byte
                count = count + 1

            count = 0
            mpc_fullname = ''
            while 1:
                byte = struct.unpack('=c', self.x86_mem_pae.read(mac_conf[1] + count, 1))[0]
                if byte == '\x00':
                    break
                mpc_fullname = mpc_fullname + byte
                count = count + 1

            # get mpc_labelnames
            for label_offset in range(0, mac_conf[3]):
                mac_label_ptr = self.x86_mem_pae.read(mac_conf[2]+(label_offset*Pointer[0]), Pointer[0])
                mac_label = struct.unpack(Pointer[1], mac_label_ptr)[0]
                #print '%x'%self.x86_mem_pae.vtop(mac_label)

            if self.arch == 32:
                if self.osversion == 10:
                    mac_ops_ptr = self.x86_mem_pae.read(mac_conf[4], 314*Pointer[0])
                    mac_ops = struct.unpack('=314I', mac_ops_ptr)
                else:
                    mac_ops_ptr = self.x86_mem_pae.read(mac_conf[4], 335*Pointer[0])
                    mac_ops = struct.unpack('=335I', mac_ops_ptr)
            else: # 64
                if self.osversion == 10:
                    mac_ops_ptr = self.x86_mem_pae.read(mac_conf[4], 314*Pointer[0])
                    mac_ops = struct.unpack('=314Q', mac_ops_ptr)
                else:
                    mac_ops_ptr = self.x86_mem_pae.read(mac_conf[4], 335*Pointer[0])
                    mac_ops = struct.unpack('=335Q', mac_ops_ptr)

            #print 'mpc_name: %s'%mpc_name
            #print 'mpc_fullname: %s'%mpc_fullname
            #print 'mpc_labelnames: %x'%self.x86_mem_pae.vtop(mac_conf[2])
            #print 'mpc_labelname_count: %d'%mac_conf[3]
            #print 'mpc_ops: %x'%self.x86_mem_pae.vtop(mac_conf[4])
            #print 'mpc_loadtime_flags: %d'%mac_conf[5]
            #print 'mpc_runtime_flags: %d'%mac_conf[7]

            mac_conf_data.append(mpc_name)
            mac_conf_data.append(mpc_fullname)
            mac_conf_data.append(self.get_loadtime_flag(mac_conf[5]))
            mac_conf_data.append(self.get_runtime_flag(mac_conf[7]))
            mac_conf_data.append(self.mac_ops_sort(mac_ops))

            policy_list.append(mac_conf_data)
    
        return policy_list, mac_policy_structure

    # http://www.freebsd.org/doc/en/books/arch-handbook/mac-entry-point-reference.html
    def mac_ops_sort(self, mac_ops_list):
        new_mac_ops_list = []
        count = 0
        for mac_ops in mac_ops_list:
            if mac_ops == 0:
                count = count + 1
                continue
            if self.osversion == 10:
                temp_list = [ops_func_pointer_sl[count], mac_ops, self.x86_mem_pae.vtop(mac_ops)]
            else:
                temp_list = [ops_func_pointer_lion[count], mac_ops, self.x86_mem_pae.vtop(mac_ops)]
            new_mac_ops_list.append(temp_list) # VA, PA
            count = count + 1

        return new_mac_ops_list

    def get_loadtime_flag(self, num):
        if num == 0x00000001:
            return 'MPC_LOADTIME_FLAG_NOTLATE'
        elif num == 0x00000002:
            return 'MPC_LOADTIME_FLAG_UNLOADOK'
        elif num == 0x00000004:
            return 'MPC_LOADTIME_FLAG_LABELMBUFS'
        elif num == 0x00000008:
            return 'MPC_LOADTIME_BASE_POLICY'
        else:
            return 'unknown'

    def get_runtime_flag(self, num):
        if num == 0x00000001:
            return 'MPC_RUNTIME_FLAG_REGISTERED'
        else:
            return 'unknown'

#################################### PUBLIC FUNCTIONS ####################################

def print_mac_policy_list(data_list, mac_policy, kext_list):
    print '[+] TrustedBSD MAC Framework on Darwin'
    print 'Loaded Policy Count: %d, Max Count: %d, Current Policy Count: %d'%(mac_policy[0], mac_policy[1], mac_policy[2])
    print '--------------------------------------------------------------------------------'
    
    for data in data_list:
        print 'Name: %s, Full Name: %s'%(data[0], data[1])
        print 'Loadtime : %s, Runtime: %s'%(data[2], data[3])
        print '--------------------------------------------------------------------------------'
        kext = []
        headerlist = ["Entrypoint", "Virtual Address", "Physical Address", ""]
        contentlist = []
        for mac_ops in data[4]:
            line = ['%s'%mac_ops[0]]
            line.append('0x%.8X'%mac_ops[1])
            line.append('0x%.8X'%mac_ops[2])
            contentlist.append(line)
            #print '%s, VA: 0x%.8x, PA: 0x%.8x'%(mac_ops[0], mac_ops[1], mac_ops[2])
            if len(kext) == 0:
                for data in kext_list:
                    if (mac_ops[1] >= data[7]) and (mac_ops[1] <= data[7]+data[8]):
                        kext.append(data[3]) # name
                        kext.append(data[7]) # address
                        kext.append(data[8]) # size
                        kext.append(data[2])
                        break
            line.append('')
        mszlist = [-1, -1, -1, -1]
        columnprint(headerlist, contentlist, mszlist) 
        print '--------------------------------------------------------------------------------'
        if len(kext) == 4:
            print '[+] Associated KEXT : %s (0x%.8x-0x%.8x) - ID: %d'%(kext[0], kext[1], kext[1] + kext[2], kext[3])
        else:
            print 'Can not find associated KEXT!!'
        print '--------------------------------------------------------------------------------'
        print ''

    print 'If you want to dump associated KEXT, please to use "kextstat" with "-x ID"'

def get_mac_policy_table(x86_mem_pae, sym_addr, arch, os_version, build, base_address):
    mac_policy_class = trustedbsd(x86_mem_pae, arch, build, base_address, os_version)
    mac_policy_list, mac_policy_structure = mac_policy_class.get_mac_policy_list(sym_addr)
    return mac_policy_list, mac_policy_structure
