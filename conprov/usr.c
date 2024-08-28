#include <sys/resource.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#include "usr/conprov.skel.h"
#include "usr/configuration.h"
#include "usr/record.h"
#include "usr/docker.h"
#include "shared/common.h"
#include "cJSON/cJSON.h"
#include "usr/utils.h"
#include "shared/prov_struct.h"
#include "usr/types.h"
#include "shared/prov_types.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434   /* System call # on most architectures */
#endif

static struct conprov *skel = NULL;
static struct container_event container_info;

static void sig_handler(int sig)
{
    if (sig == SIGTERM)
    {
        syslog(LOG_INFO, "ConProv: Received termination signal...");
        conprov__destroy(skel);
        syslog(LOG_INFO, "ConProv: Good bye!");
        exit(0);
    }
}

static void update_rlimit(void)
{
    int err;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    err = setrlimit(RLIMIT_MEMLOCK, &r);
    if (err)
    {
        syslog(LOG_ERR, "ConProv: Error while setting rlimit %d.", err);
        exit(err);
    }
}

// callback function : for response data
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    FILE *fp = (FILE *)userdata;
    return fwrite(ptr, size, nmemb, fp);
}

static int init_podman_pod(char *container_id)
{
    int map_fd;
    int key = 0;

    char url_str[200];
    char con_short_id[20];
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    strncpy(con_short_id, container_id, 6);

    char filename[] = "response.json";
    cJSON *json;

    // init libcurl
    curl = curl_easy_init();
    if (curl) {
        // setup Podman REST API 
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, "/run/podman/podman.sock");

        // setup request path
        snprintf(url_str, sizeof(url_str), "http://localhost/containers/%s/json", con_short_id);
        curl_easy_setopt(curl, CURLOPT_URL, url_str);

        // setup request header
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // open file to write response data
        FILE *fp = fopen(filename, "w");
        if (fp == NULL) {
            // fprintf(stderr, "Failed to open file for writing\n");
            return EXIT_FAILURE;
        }

        // setup callback
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fclose(fp); 
            return EXIT_FAILURE;
        }

        fclose(fp);

        fp = fopen(filename, "r");
        if (fp == NULL) {
            // fprintf(stderr, "Failed to open file for reading\n");
            return EXIT_FAILURE;
        }

        fseek(fp, 0, SEEK_END);
        long filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char *file_buffer = (char *)malloc(filesize + 1);
        if (file_buffer == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            fclose(fp);
            return EXIT_FAILURE;
        }

        fread(file_buffer, 1, filesize, fp);
        file_buffer[filesize] = '\0';
        fclose(fp);

        json = cJSON_Parse(file_buffer);
        if (json) {
            cJSON *state = cJSON_GetObjectItem(json, "State");
            if (state) {
                cJSON *pid = cJSON_GetObjectItem(state, "Pid");
                if (pid) {
                    // printf("State.Pid: %d\n", pid->valueint);
                    key = pid->valueint;
                    struct process_event process_info;
                    process_info.pid = pid->valueint;
                    // fprintf(stderr, "process_pid: %d\n", process_info.pid);
                    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "processes");
                    bpf_map_update_elem(map_fd, &key, &process_info, BPF_ANY);
                    skel->bss->key_count += 1;
                } else {
                    printf("State.Pid field not found\n");
                }
            } else {
                printf("State field not found\n");
            }
            cJSON *graph_driver = cJSON_GetObjectItem(json, "GraphDriver");
            if(graph_driver){
                cJSON *data = cJSON_GetObjectItem(graph_driver, "Data");
                if (data) {
                    char *rootfs = cJSON_GetObjectItem(data, "MergedDir")->valuestring;
                    if (rootfs != NULL)
                    {
                        ro_path = rootfs;
                        // fprintf(stderr, "rootfs: %s  \n", ro_path);
                    }
                } else {
                    printf("GraphDriver.Data field not found\n");
                }
            }else {
                printf("GraphDriver field not found\n");
            }
            cJSON_Delete(json);
        } else {
            printf("Failed to parse JSON\n");
        }

        free(file_buffer);
    } else {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return EXIT_FAILURE;
    }

    curl_easy_cleanup(curl);

    curl_slist_free_all(headers);

    return 0;
    
}

static int init_container_map(char *container_id)
{
    int map_fd;
    int key = 0;

    DOCKER *docker = docker_init("v1.25");
    CURLcode response;
    if (docker)
    {
        strcpy(container_info.container_id, container_id);
        printf("The following are the process present in the container.\n");
        char url_str[200] = "http://v1.25/containers/";
        char con_short_id[20];
        strncpy(con_short_id, container_id, 6);
        strcat(url_str, strcat(con_short_id, "/top"));
        response = docker_get(docker, url_str);
        // fprintf(stderr, "%s\n", url_str);
        if (response == CURLE_OK)
        {
            // fprintf(stderr, "%s\n", docker_buffer(docker));
            char *docker_top = docker_buffer(docker);
            cJSON *docker_json = cJSON_Parse(docker_top);
            if (docker_json == NULL)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL)
                {
                    syslog(LOG_ERR, "ConProv: Error before docker top buffer parsing: %s.\n", error_ptr);
                }
                return 0;
            }
            cJSON *docker_process = cJSON_GetObjectItem(docker_json, "Processes");
            int process_size = cJSON_GetArraySize(docker_process);
            for (int i = 0; i < process_size; i++)
            {
                cJSON *process_array = cJSON_GetArrayItem(docker_process, i);
                if (process_array != NULL)
                {
                    strcpy(container_info.process.uid, cJSON_GetArrayItem(process_array, 0)->valuestring);
                    strcpy(container_info.process.cmd, cJSON_GetArrayItem(process_array, 7)->valuestring);
                    char *process_pid = cJSON_GetArrayItem(process_array, 1)->valuestring;
                    char *process_ppid = cJSON_GetArrayItem(process_array, 2)->valuestring;
                    sscanf(process_pid, "%d", &container_info.process.pid);
                    sscanf(process_ppid, "%d", &container_info.process.ppid);
                    container_info.process.is_container = 1;
                    key = container_info.process.pid;
                    struct process_event process_info;
                    process_info = container_info.process;
                    fprintf(stderr, "process_uid: %s  process_pid: %d  process_ppid: %d  process_cmd: %s  \n", process_info.uid, process_info.pid, process_info.ppid, process_info.cmd);
                    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "processes");
                    bpf_map_update_elem(map_fd, &key, &process_info, BPF_ANY);
                    skel->bss->key_count += 1;
                }
            }
        }
        docker_destroy(docker);
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to get a docker client!\n");
        syslog(LOG_ERR, "ConProv: ERROR: Failed to get get a docker client!\n");
    }

    DOCKER *new_docker = docker_init("v1.25");
    CURLcode new_response;
    if (new_docker)
    {
        printf("Retriving rootfs of container......\n");
        char new_url_str[200] = "http://v1.25/containers/";
        char short_id[20];
        strncpy(short_id, container_id, 6);
        strcat(new_url_str, strcat(short_id, "/json"));
        new_response = docker_get(new_docker, new_url_str);
        // fprintf(stderr, "%s\n", new_url_str);
        if (new_response == CURLE_OK)
        {
            // fprintf(stderr, "%s\n", docker_buffer(new_docker));
            char *docker_info = docker_buffer(new_docker);
            cJSON *docker_json = cJSON_Parse(docker_info);
            if (docker_json == NULL)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL)
                {
                    syslog(LOG_ERR, "ConProv: Error before docker top buffer parsing: %s.\n", error_ptr);
                }
                return 0;
            }
            cJSON *docker_driver = cJSON_GetObjectItem(docker_json, "GraphDriver");
            cJSON *docker_data = cJSON_GetObjectItem(docker_driver, "Data");
            char *rootfs = cJSON_GetObjectItem(docker_data, "MergedDir")->valuestring;
            if (rootfs != NULL)
            {
                // strcat(rootfs, "/");
                ro_path = rootfs;
                // fprintf(stderr, "rootfs: %s  \n", ro_path);
            }
        }
        docker_destroy(new_docker);
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to get a docker client!\n");
        syslog(LOG_ERR, "ConProv: ERROR: Failed to get get a docker client!\n");
    }

    // Cgroup V1：retrive /proc/pid/ns inode number
    // kern.c:bpf_get_current_cgroup_ino
    if (skel->bss->key_count > 0)
    {
        if (container_info.process.pid)
        {
            char cgroup_ns[64];
            int count = 1024;
            char cgroup_inode[count];
            sprintf(cgroup_ns, "/proc/%d/ns", container_info.process.pid);
            strcat(cgroup_ns, "/cgroup");
            int rslt = readlink(cgroup_ns, cgroup_inode, count - 1);
            if (rslt < 0 || (rslt >= count - 1))
            {
                fprintf(stderr, "ERROR: Failed to get get a docker ns_info!\n");
                syslog(LOG_ERR, "ConProv: ERROR: Failed to get get a docker ns_info!\n");
            }
            cgroup_inode[rslt] = '\0';
            for (int i = rslt; i >= 0; i--)
            {
                if (cgroup_inode[i] == '/')
                {
                    cgroup_inode[i + 1] = '\0';
                    break;
                }
            }
            fprintf(stderr, "cgroup_inode: %s\n", cgroup_inode);
            char *freq_split;
            freq_split = strtok(cgroup_inode, "[");
            if (freq_split)
            {
                freq_split = strtok(NULL, "]");
                // printf("%s\n", freq_split);
            }
            container_info.namespace.cgroup_namespace = String2Int(freq_split);
            struct namespace_info ns_info;
            ns_info = container_info.namespace;
            // fprintf(stderr, "cgroup_namespace: %ld \n", ns_info.cgroup_namespace);
            map_fd = bpf_object__find_map_fd_by_name(skel->obj, "nsinfos");
            key = 1;
            bpf_map_update_elem(map_fd, &key, &ns_info, BPF_ANY);
        }
        else
        {
            fprintf(stderr, "ERROR: Failed to get get a docker ns_info!\n");
            syslog(LOG_ERR, "ConProv: ERROR: Failed to get get a docker ns_info!\n");
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to get docker's pid!\n");
        syslog(LOG_ERR, "ConProv: ERROR: Failed to get docker's pid!\n");
    }

    fprintf(stderr, "container_id:%s\n", container_id);
    // Cgroup V2：use $cg2 to update cgroup_map
    // if exists /sys/fs/cgroup/cgroup.controllers, it's cgroup v2.
    // access success returns 0
    if ((access("/sys/fs/cgroup/cgroup.controllers", 0)) != -1)
    {
        int ret = -1;
        char cg2_str[200] = "/sys/fs/cgroup/system.slice/docker-";
        const char *cg2 = strcat(strcat(cg2_str, container_id), ".scope/");
        // fprintf(stderr, "cg2:%s\n", cg2);
        FILE *fp;
        int fno;
        fp = fopen(cg2, "r");
        if (fp != NULL)
        {
            fno = fileno(fp);
        }
        // fprintf(stderr, "fno:%d\n", fno);

        int array_fd = bpf_object__find_map_fd_by_name(skel->obj, "cgroup_map");
        bpf_map_update_elem(array_fd, &skel->bss->array_key, &fno, BPF_ANY);
        // if (ret)
        // {
        //     fprintf(stderr, "ERROR: Failed to update Cgroup map!\n");
        //     syslog(LOG_ERR, "ConProv: ERROR: Failed to update Cgroup map!\n");
        // }
    }
    else
    {
        fprintf(stderr, "ERROR: Docker doesn't use Cgroup V2!\n");
        syslog(LOG_ERR, "ConProv: ERROR: Docker doesn't use Cgroup V2!\n");
    }
    
    return 0;
}

/* Callback function called whenever a new ring
 * buffer entry is polled from the buffer. */
int handle_event(void *ctx, void *data, size_t data_sz)
{
    union long_prov_elt *prov = (union long_prov_elt *)data;

    /* Userspace processing the provenance record. */
    bpf_prov_record(prov);

    return 0;
}

int main(void)
{
    struct ring_buffer *ringbuf = NULL;
    int err, map_fd;
    int processes_fd;

    syslog(LOG_INFO, "ConProv: Starting...");
    syslog(LOG_INFO, "ConProv: Registering signal handler...");
    signal(SIGTERM, sig_handler);
    syslog(LOG_INFO, "ConProv: Reading Configuration...");
    read_config();

    syslog(LOG_INFO, "ConProv: Setting rlimit...");
    update_rlimit();

    syslog(LOG_INFO, "ConProv: Open and loading...");
    skel = conprov__open_and_load();
    if (!skel)
    {
        syslog(LOG_ERR, "ConProv: Failed loading bpf skeleton.");
        goto close_prog;
    }

    syslog(LOG_INFO, "ConProv: Attaching BPF programs...");
    err = conprov__attach(skel);
    if (err)
    {
        syslog(LOG_ERR, "ConProv: Failed attaching %d.", err);
        goto close_prog;
    }

    syslog(LOG_INFO, "ConProv: initializing container information...");
    // char container_id[MAX_CONTAINER_LEN] = "4dc407fc29c232a6878d36af50ef73a552efbe8176096aeccdae62db3c034e8f";
    char container_id[65];
    printf("Please input the Id of the specific contianer: ");
    scanf("%64s", container_id);
    err = init_container_map(container_id);
    // err = init_podman_pod(container_id);
    if (err)
    {
        syslog(LOG_ERR, "ConProv: Failed initializing container information.");
        goto close_prog;
    }

    /* Locate ring buffer */
    syslog(LOG_INFO, "ConProv: Locating the ring buffer...");
    map_fd = bpf_object__find_map_fd_by_name(skel->obj, "r_buf");
    if (map_fd < 0)
    {
        syslog(LOG_ERR, "ConProv: Failed loading ring buffer (%d).", map_fd);
        goto close_prog;
    }
    syslog(LOG_INFO, "ConProv: Setting up the ring buffer in userspace...");

    prov_record_init();

    ringbuf = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    syslog(LOG_INFO, "ConProv: Start polling forever...");

    /* Container events */

    while (ring_buffer__poll(ringbuf, -1) >= 0)
    {
        prov_refresh_records();
    }

close_prog:
    ring_buffer__free(ringbuf);
    conprov__destroy(skel);

    return 0;
}