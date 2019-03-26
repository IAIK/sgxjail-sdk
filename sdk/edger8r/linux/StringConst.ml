let get_str_add_includes_enclave_u_c = "\
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>

#define SHM_OBJ_PERMISSIONS 0644 
#define SHM_OBJ_SIZE       4096*3  
#define SHM_OBJ_NAME_SIZE  64    
" 

let get_str_sandbox_init_encalve_u_c = "\
void sandbox_ocall_dispatch(void); 

void * ocall_dispatcher(void* r_f_u) 
{
  (void)r_f_u;

  while(1) {
    sem_wait(&(msg_ocall->sem_call));
    sandbox_ocall_dispatch();
    sem_post(&(msg_ocall->sem_ret));

    if(msg_ocall->call == 686868) {
      break;
    }
  }
  return NULL;
}

char sandbox_ecall_shm_obj_name[SHM_OBJ_NAME_SIZE];
char sandbox_ocall_shm_obj_name[SHM_OBJ_NAME_SIZE];

sgx_status_t sandbox_create_enclave(const char *file_name,
                                    const int debug,
                                    sgx_launch_token_t *launch_token,
                                    int *launch_token_updated,
                                    sgx_enclave_id_t *enclave_id,
                                    sgx_misc_attribute_t *misc_attr)
{
    (void)file_name;
    (void)debug;
    (void)launch_token;
    (void)enclave_id;
    (void)misc_attr;
    char name[64];
    sprintf(name, \"enclave_%d\", getpid());
    sprintf(sandbox_ecall_shm_obj_name, \"%s_ecall\", name);
    sprintf(sandbox_ocall_shm_obj_name, \"%s_ocall\", name);

    int shm_obj_ecall = shm_open(sandbox_ecall_shm_obj_name, O_CREAT | O_RDWR, SHM_OBJ_PERMISSIONS);
    int shm_obj_ocall = shm_open(sandbox_ocall_shm_obj_name, O_CREAT | O_RDWR, SHM_OBJ_PERMISSIONS);

    if(shm_obj_ecall == -1 || shm_obj_ocall == -1) {
        printf(\"Could not get shared memory object\\n\");
        return 1;
    }

    ftruncate(shm_obj_ecall, SHM_OBJ_SIZE);
    ftruncate(shm_obj_ocall, SHM_OBJ_SIZE);

    MSG_ECALL(eid) = (SEMsg*) mmap(NULL, SHM_OBJ_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shm_obj_ecall, 0);
    MSG_OCALL(eid) = (SEMsg*) mmap(NULL, SHM_OBJ_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, shm_obj_ocall, 0);

    if(!msg_ecall || !msg_ocall) {
        printf(\"Failed to map shared memory\\n\");
        return 1;
    }

    MSG_ECALL(eid)->call = (uint64_t) -1;
    MSG_OCALL(eid)->call = (uint64_t) -1;

    sem_init(&(MSG_ECALL(eid)->sem_call),   1, 0);
    sem_init(&(MSG_ECALL(eid)->sem_ret), 1, 0);
    sem_init(&(MSG_OCALL(eid)->sem_call),   1, 0);
    sem_init(&(MSG_OCALL(eid)->sem_ret), 1, 0);

    if(fork() == 0) {
        printf(\"[H] Starting enclave\\n\");
        char* const arg[] = {\"app_s\", name, NULL};
        execv(arg[0], arg);
        printf(\"[H] FAILED!\\n\");
    } else {
        pthread_t d;
        pthread_create(&d, NULL, ocall_dispatcher, NULL);
    }

    return 0;
}\n\n"

let get_str_sandbox_init_encalve_u_h = "\
sgx_status_t sandbox_create_enclave(const char *file_name,
                                    const int debug,
                                    sgx_launch_token_t *launch_token,
                                    int *launch_token_updated,
                                    sgx_enclave_id_t *enclave_id,
                                    sgx_misc_attribute_t *misc_attr);
"

let get_str_sandbox_destroy_encalve_u_c = "\
    sgx_status_t sandbox_destroy_enclave(sgx_enclave_id_t eid)
    {
        msg_ecall->call = 9999;
        sem_post(&(MSG_ECALL(eid)->sem_call));
        return MSG_ECALL(eid)->result;
    }\n"

let get_str_sandbox_destroy_encalve_u_h = "\
sgx_status_t sandbox_destroy_enclave(sgx_enclave_id_t eid);
"

let func_string = "size_t write_to_shm(size_t* param_ptr, char size)
    {
    \tchar idy = 0;
    \t\tdo
    \t\t{
    \t\t\tif(msg_ocall->param[idx] == 0)
    \t\t\t{
    \t\t\t\tif(idx == 0)
    \t\t\t\t{
    \t\t\t\t\tmsg_ocall->param[0] = memcpy(msg_ocall->data, msg_ocall->param[0], size);
    \t\t\t\t\tmsg_ocall->param[1] = msg_param[0] + size;
    \t\t\t\t\treturn 0;
    \t\t\t\t}
    \t\t\t\telse
    \t\t\t\t{
    \t\t\t\t\tif(idx <= 4)
    \t\t\t\t\t{
    \t\t\t\t\t\tmsg_ocall->param[idx] = memcpy(msg_ocall->param[idx] + 1, msg_ocall->param[idx], size);
    \t\t\t\t\t\tmsg_ocall->param[idx + 1] = msg_ocall->param[idx] + size;
    \t\t\t\t\t\treturn 0;
    \t\t\t\t\t}
    \t\t\t\t\tif(idx == 5)
    \t\t\t\t\t{
    \t\t\t\t\t\tmemset(msg_ocall->param[idx] + 1, 0, 16);
    \t\t\t\t\t\treturn -1;
    \t\t\t\t\t}
    \t\t\t\t}
    \t\t\t}
    \t\t}while(idy < 6);
    }\n\n"  


let get_app_s_cpp_defines =  "#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <semaphore.h>
#include <seccomp.h>
#include <stdio.h>
#include <sgx_urts.h>
#include \"Enclave_us.h\"

#define SHM_OBJ_PERMISSIONS 0644
#define SHM_OBJ_SIZE        (4096 * 3)
#define SHM_OBJ_NAME_SIZE   64

#define ENCLAVE_FILE \"enclave.signed.so\"
"

let get_app_s_cpp_body = "
char ecall_name[SHM_OBJ_NAME_SIZE];
char ocall_name[SHM_OBJ_NAME_SIZE];

int sandbox_init(int argc, char* argv[])
{
  if(argc < 2) {
    printf(\"Sandbox: need to specify shared memory key\\n\");
    return 1;
  }

  snprintf(ecall_name, sizeof(ecall_name), \"%s_ecall\", argv[1]);
  snprintf(ocall_name, sizeof(ocall_name), \"%s_ocall\", argv[1]);

  int s_e = shm_open(ecall_name, O_RDWR, SHM_OBJ_PERMISSIONS);
  int s_o = shm_open(ocall_name, O_RDWR, SHM_OBJ_PERMISSIONS);

  if(s_e == -1 || s_o == -1) {
    printf(\"Sandbox: Could not open shared memory\\n\");
    return 2;
  }

  msg_ecall = (SEMsg*)mmap(NULL, SHM_OBJ_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_e, 0);
  msg_ocall = (SEMsg*)mmap(NULL, SHM_OBJ_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, s_o, 0);

  if(!msg_ecall || !msg_ocall) {
    printf(\"Sandbox: Could not map shared memory\\n\");
    return 3;
  }
  return 0;
}

int main(int argc, char* argv[])
{
  sgx_status_t ret = SGX_SUCCESS;
  sgx_launch_token_t token = {0};
  int updated = 0;

  if(sandbox_init(argc, argv)) {
    printf(\"Sandbox: Unable to initialize sandbox\\n\");
    return -1;
  }

  ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    printf(\"Sandbox: Unable to create enclave. Failed with %d\\n\", ret);
  }

  prctl(PR_SET_NO_NEW_PRIVS, 1);
  prctl(PR_SET_DUMPABLE, 0);
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_load(ctx);

  /* From now on we cannot do any syscalls except futex and exit_group */

  while (1) {
    sem_wait(&(msg_ecall->sem_call));
    sandbox_ecall_dispatch();
    sem_post(&(msg_ecall->sem_ret));

    if (msg_ecall->call == 9999) {
      break;
    }
  }

  sgx_destroy_enclave(global_eid);

  munmap(msg_ocall, 4096);
  munmap(msg_ocall, 4096);

  shm_unlink(ecall_name);
  shm_unlink(ocall_name);

  return 0;
}
"
