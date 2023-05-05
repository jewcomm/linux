#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <asm/unistd32.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <linux/memory.h>
#include <linux/types.h>

#include <linux/tee_drv.h>
#include <linux/hw_random.h>

#define PTA_SYS_CALL_SAVER 1

// static const uuid_t optee_rng_id_table = 
// 	UUID_INIT(0xe73c0f36, 0x3753, 0x40ce,
// 	  0xa0, 0xe9, 0x4d, 0x3c, 0x55, 0x79, 0x73, 0x92);

static const uuid_t optee_rng_id_table = 
	UUID_INIT(0x2a38dd39, 0x3414, 0x4b58, 
  0xa3, 0xbd, 0x73, 0x91, 0x8a, 0xe6, 0x2e, 0x68);

static int ftpm_tee_match(struct tee_ioctl_version_data *ver, const void *data)
{
	/*
	 * Currently this driver only support GP Complaint OPTEE based fTPM TA
 	 */
	if ((ver->impl_id == TEE_IMPL_ID_OPTEE) &&
		(ver->gen_caps & TEE_GEN_CAP_GP))
		return 1;
	else
		return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Navrotskij");
MODULE_DESCRIPTION("Simple Hello World module!");
MODULE_VERSION("0.1");

static int __init hello_start(void){
    printk(KERN_INFO "Loading hello module...\n");

    unsigned long compat_syscal = kallsyms_lookup_name("compat_sys_call_table");
    unsigned long * compat_syscal_ptr = (unsigned long *)compat_syscal; 
    printk(KERN_INFO "compat_sys_call_table ul value: %lx\n", compat_syscal);
    printk(KERN_INFO "compat_sys_call_table ptr value: %p\n", compat_syscal_ptr);

    phys_addr_t syscall_phys = virt_to_phys(compat_syscal_ptr);

    printk(KERN_INFO "compat_sys_call_table ptr value: %lx\n", syscall_phys);

    for (int i = 0; i < 1; i++){
      unsigned long t = compat_syscal_ptr[i];
      printk(KERN_INFO "[my syscall parser] compat_sys_call_table[%i]: %lx\n", i, t);
    }

    struct tee_context *ctx = tee_client_open_context(NULL, ftpm_tee_match, NULL, NULL);
    if(IS_ERR(ctx)){
      if(PTR_ERR(ctx) == -ENOENT) return -EPROBE_DEFER;
      return PTR_ERR(ctx);
    }

    struct tee_ioctl_open_session_arg sess_arg;
    memset(&sess_arg, 0, sizeof(sess_arg));
	  export_uuid(sess_arg.uuid, &optee_rng_id_table);
    sess_arg.clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	  sess_arg.num_params = 0;

    int rc = tee_client_open_session(ctx, &sess_arg, NULL);
    if((rc < 0) || (sess_arg.ret != 0)) {
      rc = -EINVAL;
      goto out_tee_session;
    }

    struct tee_ioctl_invoke_arg transceive_args;
    memset(&transceive_args, 0, sizeof(transceive_args));
    transceive_args.func = PTA_SYS_CALL_SAVER;
    transceive_args.session = sess_arg.session;
    transceive_args.num_params = 4;

    struct tee_param command_params[4];
    memset(command_params, 0, sizeof(command_params));

    __u32 compat_syscall_count = __NR_compat_syscalls;

    command_params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
    command_params[0].u.value.a = syscall_phys;
    command_params[0].u.value.b = compat_syscall_count;

    rc = tee_client_invoke_func(ctx, &transceive_args, command_params);

    tee_client_close_session(ctx, sess_arg.session);
    out_tee_session:
	  tee_client_close_context(ctx);

    printk(KERN_INFO "END MY DRVR!\n");

    return 0;
}

static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye\n");
}
  
module_init(hello_start);
module_exit(hello_end);