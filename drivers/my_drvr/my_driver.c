#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/kallsyms.h>   /* Needed for the kallsyms_lookup_name */
#include <asm/syscall.h>      /* Needed for the __NR_compat_syscalls */
#include <linux/types.h>      
#include <linux/tee_drv.h>    /* Needed for connect with PTA */
#include <asm/unistd32.h>

#ifndef DEBUG_SYSCALL_SENDER
#define DEBUG_SYSCALL_SENDER 1
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Navrotskij");
MODULE_DESCRIPTION("Linux module transmitting syscall address to OPTEE");
MODULE_VERSION("0.1");

#define PTA_SYS_CALL_SAVER 1

static const uuid_t optee_syscall_pta_uuid = 
    UUID_INIT(0x2a38dd39, 0x3414, 0x4b58, 
        0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68);

static int syscall_pta_match(struct tee_ioctl_version_data *ver, 
                            const void *data)
{
	if ((ver->impl_id == TEE_IMPL_ID_OPTEE) &&
		(ver->gen_caps & TEE_GEN_CAP_GP))
		return 1;
	else
		return 0;
}

static int __init hello_start(void)
{
    /* syscall */
    unsigned long * compat_syscal_ptr;
    phys_addr_t compat_syscall_phys;
    __u32 compat_syscall_count = __NR_compat_syscalls;

    /* tee */
    struct tee_context *ctx;
    struct tee_ioctl_open_session_arg sess_arg;
    struct tee_ioctl_invoke_arg transceive_args;
    struct tee_param command_params[4];

    int rc;

    printk(KERN_INFO "Loading syscall sender module...\n");

    compat_syscal_ptr = (unsigned long *)kallsyms_lookup_name("compat_sys_call_table");
    printk(KERN_INFO "compat_sys_call_table ptr value: %p\n", compat_syscal_ptr);

    /* analyzed later, see sys32.c and syscall.h */
    // printk(KERN_INFO "compat_sys_call_table ptr value: %p\n", &compat_sys_call_table);
    // for(int i = 0; i < __NR_compat_syscalls; i++){
    //     printk(KERN_INFO "[my syscall parser] compat_sys_call_table[%i]: %lx\n", i, compat_sys_call_table[i]);
    // }

    compat_syscall_phys = virt_to_phys(compat_syscal_ptr);

    printk(KERN_INFO "compat_sys_call_table phys value: %lx\n", compat_syscall_phys);

    for (int i = 0; i < 1; i++){
        unsigned long t = compat_syscal_ptr[i];
        printk(KERN_INFO "[my syscall parser] compat_sys_call_table[%i]: %lx\n", i, t);
    }

    ctx = tee_client_open_context(NULL, syscall_pta_match, NULL, NULL);
    if(IS_ERR(ctx)){
        if(PTR_ERR(ctx) == -ENOENT) return -EPROBE_DEFER;
        return PTR_ERR(ctx);
    }

    memset(&sess_arg, 0, sizeof(sess_arg));
	export_uuid(sess_arg.uuid, &optee_syscall_pta_uuid);
    sess_arg.clnt_login = TEE_IOCTL_LOGIN_REE_KERNEL;
	sess_arg.num_params = 0;

    rc = tee_client_open_session(ctx, &sess_arg, NULL);
    if((rc < 0) || (sess_arg.ret != 0)) {
        rc = -EINVAL;
        goto out_tee_session;
    }

    memset(&transceive_args, 0, sizeof(transceive_args));
    transceive_args.func = PTA_SYS_CALL_SAVER;
    transceive_args.session = sess_arg.session;
    transceive_args.num_params = 4;

    memset(command_params, 0, sizeof(command_params));

    command_params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
    command_params[0].u.value.a = compat_syscall_phys;
    command_params[0].u.value.b = compat_syscall_count;

    rc = tee_client_invoke_func(ctx, &transceive_args, command_params);

    tee_client_close_session(ctx, sess_arg.session);
    out_tee_session:
	tee_client_close_context(ctx);

    printk(KERN_INFO "END syscall sender module\n");

    return 0;
}

static void __exit hello_end(void)
{
}
  
module_init(hello_start);
module_exit(hello_end);