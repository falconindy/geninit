#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

/* util-linux */
#include <blkid/blkid.h>

#define msg(...) {if (!quiet) fprintf(stderr, ":: " __VA_ARGS__);}
#define err(...) {fprintf(stderr, "error: " __VA_ARGS__);}
#define die(...) {err(__VA_ARGS__); _exit(1);}

#define CMDLINE_SIZE  257       /* 256 max cmdline len + NULL */
#define TMPFS_FLAGS   MS_NOEXEC|MS_NODEV|MS_NOSUID

#define NEWROOT       "/new_root"
#define BUSYBOX       "/bin/busybox"
#define UDEVD         "/sbin/udevd"
#define UDEVADM       "/sbin/udevadm"
#define MODPROBE      "/sbin/modprobe"

int rootflags = 0;
int quiet = 0;

/* utility */
static dev_t hex2dev(char *hexstring) { /* {{{ */
  char *endptr;
  char hexmajor[3], hexminor[3];
  long major, minor;
  size_t len;

  len = strlen(hexstring);
  if (len > 4) {
    return 1;
  }

  /* 2 less than the length, plus a NULL */
  snprintf(hexmajor, len - 2 + 1, "%s", hexstring);

  /* leave off after the major, 2 chars plus a NULL */
  snprintf(hexminor, 3, "%s", hexstring + len - 2);

  major = strtol(hexmajor, &endptr, 16);
  if (!endptr) {
    return makedev(0, 0);
  }

  minor = strtol(hexminor, &endptr, 16);
  if (!endptr) {
    return makedev(0, 0);
  }

  return makedev(major, minor);
} /* }}} */

static int forkexecwait(char **argv) { /* {{{ */
  pid_t pid;
  int statloc;

  pid = vfork();
  if (pid == -1) {
    perror("fork");
    return errno;
  }

  if (pid == 0) {
    execv(argv[0], argv);
    fprintf(stderr, "exec: %s: %s\n", argv[0], strerror(errno));
    _exit(errno); /* avoid flushing streams */
  }

  /* block for process exit */
  waitpid(pid, &statloc, 0);

  if (WIFEXITED(statloc) > 0) {
    return WEXITSTATUS(statloc);
  }

  /* should do a better job of this */
  return 1;
} /* }}} */

static char *sanitize_var(char *var) { /* {{{ */
  char *p;

  /* special attention to first letter */
  p = var;
  if (!(isalpha(*p) || *p == '_')) {
    /* invalid var name, can't use this */
    return NULL;
  }

  while (*++p) {
    if (isalnum((unsigned char)*p) || *p == '_') {
      /* valid character */
      continue;
    }

    if (*p == '=') {
      /* stop here, don't mangle the values */
      return var;
    }

    if (*p == '.' || *p == '-') {
      /* sanitizable */
      *p = '_';
    } else {
      /* gfy */
      return NULL;
    }
  }

  return var;
} /* }}} */

static void delete_contents(char *path, dev_t rootdev) { /* {{{ */
  DIR *dir;
  char name[PATH_MAX];
  struct dirent *dp;
  struct stat st;

  /* Don't descend into other filesystems */
  if (lstat(path, &st) || st.st_dev != rootdev) {
    return;
  }

  /* Recursively delete the contents of directories */
  if (S_ISDIR(st.st_mode)) {
    dir = opendir(path);
    if (dir) {
      while ((dp = readdir(dir))) {
        if (dp->d_ino) {
          if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            snprintf(name, PATH_MAX, "%s/%s", path, dp->d_name);
            delete_contents(name, rootdev);
          }
        }
      }
      closedir(dir);

      /* dir should now be empty, zap it */
      rmdir(path);
    }
  } else {
    /* It wasn't a dir, zap it */
    unlink(path);
  }
} /* }}} */

static void start_rescue_shell(void) { /* {{{ */
  static char *bboxinstall[] = { BUSYBOX, "--install", NULL };
  static char *bboxlaunch[] = { BUSYBOX, "ash", NULL };

  if (access(BUSYBOX, X_OK) != 0) {
    return;
  }

  /* install symlinks */
  forkexecwait(bboxinstall);

  /* set a prompt */
  putenv("PS1=[ramfs \\W]\\$ ");

  /* start the shell */
  forkexecwait(bboxlaunch);

} /* }}} */

static char *probe_fstype(const char *devname) { /* {{{ */
  int ret;
  char *fstype;
  blkid_probe pr;

  pr = blkid_new_probe_from_filename(devname);
  if (!pr) {
    err("%s: failed to create a new libblkid probe\n", devname);
    return NULL;
  }

  blkid_probe_enable_superblocks(pr, 1);
  blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_TYPE);

  ret = blkid_do_safeprobe(pr);
  if (ret == -1) {
    return NULL;
  } else if (ret == 1) {
    err("failed to probe device %s\n", devname);
    return NULL;
  } else {
    const char *name, *data;
    blkid_probe_get_value(pr, 0, &name, &data, NULL);
    fstype = strdup(data);
  }

  blkid_free_probe(pr);

  return fstype;
} /* }}} */

static void movemount(const char *src, const char *dest) { /* {{{ */
  /* move the mount if it exists on the real root, otherwise get rid of it */
  if (access(dest, F_OK) == 0) {
    mount(src, dest, NULL, MS_MOVE,  NULL);
  } else {
    umount2(src, MNT_DETACH);
  }
} /* }}} */

/* meat */
static void mount_setup(void) { /* {{{ */
  int ret;

  /* setup basic filesystems */
  mount("proc", "/proc", "proc", TMPFS_FLAGS, NULL);
  mount("sys", "/sys", "sysfs", TMPFS_FLAGS, NULL);
  mount("tmpfs", "/run", "tmpfs", TMPFS_FLAGS, "mode=1777,size=10M");

  /* ENODEV returned on non-existant FS */
  ret = mount("udev", "/dev", "devtmpfs", MS_NOSUID, "mode=0755,size=10M");
  if (ret == -1 && errno == ENODEV) {
    /* devtmpfs not available, use standard tmpfs */
    mount("udev", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=10M");

    /* create necessary nodes
     * crw------- 1 root root 5, 1 Apr  2 18:30 /dev/console
     * crw-rw-rw- 1 root root 1, 3 Apr  2 18:30 /dev/null
     * crw-rw-rw- 1 root root 1, 5 Apr  2 18:30 /dev/zero
     */
    mknod("/dev/console", S_IFCHR|0600, makedev(5, 1));
    mknod("/dev/null", S_IFCHR|0666, makedev(1, 3));
    mknod("/dev/zero", S_IFCHR|0666, makedev(1, 5));
    mknod("/dev/mem", S_IFCHR|0640, makedev(1, 1));
  }
} /* }}} */

static void put_cmdline(void) { /* {{{ */
  char cmdline[CMDLINE_SIZE], token[CMDLINE_SIZE];
  char quoted = '\0';
  char *c, *tp;
  int isvar = 0;
  FILE *fp;

  /* a bit of pointer/var hell going on...
   *   c = pointer along contents of /proc/cmdline
   *   token = container for current token being parsed
   *   tp = pointer along contents of token
   */

  fp = fopen("/proc/cmdline", "r");
  if (!fp) {
    return;
  }

  if (!fgets(cmdline, CMDLINE_SIZE, fp)) {
    return;
  }
  fclose(fp);

  tp = token;
  for (c = cmdline; *c; c++) {
    if (*c == '#') { /* full stop! */
      break;
    }

    if (isspace((unsigned char)*c)) {
      /* don't break inside a quoted region */
      if (!quoted && tp != token) {
        *tp = '\0';
        if (sanitize_var(token)) {
          if (isvar) {
            putenv(strdup(token));
          } else {
            setenv(strdup(token), "y", 1);
          }
          if (strcmp(token, "ro") == 0) {
            rootflags |= MS_RDONLY;
          } else if (strcmp(token, "quiet") == 0) {
            quiet = 1;
          }
        }
        isvar = 0;
        tp = token;
      }
      continue;
    } else if (*c == '\'' || *c == '"') {
      if (quoted) {
        if (quoted == *c) {
          quoted = '\0';
          continue;
        }
      } else {
        quoted = *c;
        continue;
      }
    }

    if (*c == '=') {
      isvar = 1;
    }

    *tp++ = *c;
  }
} /* }}} */

static void disable_modules(void) { /* {{{ */
  char *tok, *var;
  FILE *fp;

  if (getenv("disablemodules") == NULL) {
    return;
  }

  /* ensure parent dirs exist */
  mkdir("/etc", 0755);
  mkdir("/etc/modprobe.d", 0755);

  fp = fopen("/etc/modprobe.d/initcpio.conf", "w");
  if (!fp) {
    perror("error: /etc/modprobe.d/initcpio.conf");
    return;
  }

  var = strdup(getenv("disablemodules"));
  for (tok = strtok(var, ","); tok; tok = strtok(NULL, ",")) {
    fprintf(fp, "install %s /bin/false\n", tok);
  }

  fclose(fp);
  free(var);
} /* }}} */

static pid_t launch_udev(void) { /* {{{ */
  static char *argv[] = { UDEVD, "--resolve-names=never", NULL };
  pid_t pid;

  if (access(UDEVD, X_OK) != 0) {
    return 0;
  }

  msg("Starting udev...\n");

  pid = vfork();
  if (pid == -1) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    execv(argv[0], argv);
    perror("exec: " UDEVD);
    _exit(errno);
  }

  return pid;
} /* }}} */

static void load_extra_modules(void) { /* {{{ */
  FILE *fp;
  char *tok, *var;
  char **argv;
  char line[PATH_MAX];
  int modcount = 3;

  /* load early modules */
  if (getenv("earlymodules") != NULL) {
    argv = calloc(3, sizeof(argv));
    argv[0] = MODPROBE;
    argv[1] = "-qab";
    argv[2] = "--";

    var = strdup(getenv("earlymodules"));
    for (tok = strtok(var, ","); tok; tok = strtok(NULL, ",")) {
      argv = realloc(argv, sizeof(argv) * ++modcount);
      argv[modcount - 1] = tok;
    }

    if (modcount > 3) {
      argv = realloc(argv, sizeof(argv) * ++modcount);
      *(argv + (modcount - 1)) = NULL;
      forkexecwait(argv);
    }
    free(argv);
    free(var);
  }

  /* load modules from /config */
  fp = fopen("/config", "r");
  if (!fp) {
    return;
  }

  while ((fgets(line, 1024, fp))) {
    if (strncmp(line, "%MODULES%", 9) == 0) {
      strtok(line, " \n"); /* ditch the fieldname */
      tok = strtok(NULL, " \n");

      modcount = atoi(tok);
      if (!modcount) {
        break;
      }

      /* commands + number of modules + NULL */
      argv = calloc(3 + modcount + 1, sizeof argv);
      *argv++ = MODPROBE;
      *argv++ = "-qab";
      *argv++ = "--";

      while ((tok = strtok(NULL, " \n"))) {
        *argv++ = tok;
      }

      /* rewind */
      argv -= (modcount + 3);

      /* run modprobe */
      forkexecwait(argv);

      free(argv);
      break;
    }
  }

  fclose(fp);
} /* }}} */

static void trigger_udev_events(void) { /* {{{ */
  char **argv;
  static char *settle_argv[] = { UDEVADM, "settle", "--timeout=10", NULL };
  struct timeval tv[2];
  long time_ms = 0; /* processing time in ms */

  /* don't assume we have udev available */
  if (access(UDEVADM, X_OK) != 0) {
    return;
  }

  /* 4 args + NULL */
  argv = calloc(5, sizeof argv);
  argv[0] = UDEVADM;
  argv[1] = "trigger";
  argv[2] = "--action=add";
  argv[3] = strdup("--type=subsystems");

  msg("triggering uevents...\n");
  gettimeofday(&tv[0], NULL);

  /* subsystems */
  forkexecwait(argv);

  /* devices */
  free(argv[3]);
  argv[3] = "--type=devices";
  forkexecwait(argv);

  /* wait up to 10s for processing to finish */
  forkexecwait(settle_argv);

  gettimeofday(&tv[1], NULL);

  time_ms += (tv[1].tv_sec - tv[0].tv_sec) * 1000; /* s => ms */
  time_ms += (tv[1].tv_usec - tv[0].tv_usec) / 1000; /* us => ms */

  msg("finished udev processing in %ldms\n", time_ms);

  free(argv);

} /* }}} */

static void disable_hooks(void) { /* {{{ */
  char *hook, *list, *disable;

  disable = getenv("disablehooks");
  if (!disable) {
    return;
  }

  list = strdup(disable);
  for (hook = strtok(list, ", "); hook; hook = strtok(NULL, ", ")) {
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/hooks/%s", hook);

    /* mark as non-executable so run_hooks skips over it */
    chmod(path, 0644);
  }

  free(list);
} /* }}} */

static void run_hooks(void) { /* {{{ */
  FILE *fp;
  char line[PATH_MAX];
  char *hook;

  fp = fopen("/config", "r");
  if (!fp) {
    return;
  }

  while (fgets(line, PATH_MAX, fp) != NULL) {
    if (strncmp(line, "%HOOKS%", 7) == 0) {
      strtok(line, " \n"); /* ditch the fieldname */
      while ((hook = strtok(NULL, " \n"))) {
        char path[PATH_MAX];
        snprintf(path, PATH_MAX, "/hooks/%s", hook);

        if (access(path, X_OK) != 0) {
          continue;
        }

        char *argv[] = { path, path, NULL };
        forkexecwait(argv);
      }

      break;
    }
  }

  fclose(fp);
} /* }}} */

static void check_for_break(void) { /* {{{ */
  if (getenv("break") == NULL) {
    return;
  }

  msg("break requested. type 'exit' or 'logout' to resume\n");
  start_rescue_shell();
} /* }}} */

static int wait_for_root(void) { /* {{{ */
  char *rootdelay, *root;
  int delay = 0;

  root = getenv("root");
  rootdelay = getenv("rootdelay");

  if (strncmp(root, "/dev/", 5) != 0) {
    return 1; /* not a path, so it won't be found */
  }

  if (rootdelay) {
    /* atoi is "safe" here because delay<=0 is invalid */
    delay = atoi(rootdelay);
  }

  if (delay <= 0) {
    delay = 10;
  }

  msg("waiting up to %d seconds for %s ...\n", delay, root);

  delay *= 10; /* we sleep in centiseconds */
  while (delay--) {
    if (access(root, F_OK) == 0) {
      struct stat st;
      if (stat(root, &st) == 0 && S_ISBLK(st.st_mode)) {
        return 0; /* found */
      }
    }
    usleep(100000); /* .1 seconds */
  }

  return 1; /* not found */
} /* }}} */

static void try_create_root(void) { /* {{{ */
  dev_t rootdev;
  char *root;

  root = getenv("root");

  if (strncmp(root, "/dev/", 5) == 0) {
    FILE *fp;
    char path[PATH_MAX], majmin[8];

    snprintf(path, PATH_MAX, "/sys/class/block/%s", root + 6);
    if (*path && access(path, R_OK) == 0) {
      fp = fopen(path, "r"); /* this will not fail */
      fgets(majmin, 8, fp);
      fclose(fp);
      setenv("root", majmin, 1);
    }
  }

  /* intentional fallthrough from above */
  if (strchr(root, ':')) {
    /* major/minor encoding */
    char *major, *minor;

    major = minor = root;
    strsep(&minor, ":");
    rootdev = makedev(atoi(major), atoi(minor));
  } else if (strtol(root, NULL, 16) > 0) {
    rootdev = hex2dev(root);
  } else {
    /* uhhhhhhhhhhhhh .... ?? */
    err("unknown device: '%s'. You can try to create "
        "/dev/root yourself!\n", root);
    start_rescue_shell();
    printf("continuing... chance of failure = high\n");
    return;
  }

  if (mknod("/dev/root", 0660|S_IFBLK, rootdev) != 0) {
    perror("failed to create root device");
    return;
  }

  /* only set this now that /dev/root was created successfully */
  setenv("root", "/dev/root", 1);

} /* }}} */

static int mount_root(void) { /* {{{ */
  char *root, *fstype;
  int ret = 1;

  root = getenv("root");

  fstype = getenv("rootfstype");
  if (fstype) {
    return mount(root, NEWROOT, fstype, rootflags, NULL); 
  }

  fstype = probe_fstype(root);
  if (!fstype) { /* still no fstype, we're out of ideas */
    /* should hopefully never reach this */
    err("the filesystem of the root device could not be determined!\n");
    fprintf(stderr, "Try adding the rootfstype= parameter to the"
        "kernel command line\n");
    return ret;
  }

  ret = mount(root, NEWROOT, fstype, rootflags, NULL);
  free(fstype);

  return ret;
} /* }}} */

static int set_init(void) { /* {{{ */
  char path[PATH_MAX];

  /* don't overwrite, but make sure something is set */
  setenv("init", "/sbin/init", 0);

  /* existance check */
  snprintf(path, PATH_MAX, NEWROOT "%s", getenv("init"));
  return access(path, F_OK);
} /* }}} */

static void kill_udev(pid_t pid) { /* {{{ */
  static char *info_argv[] = { UDEVADM, "info", "--cleanup-db", NULL };
  static char *control_argv[] = { UDEVADM, "control", "--exit", NULL };
  char path[PATH_MAX];
  char *exe;

  if (pid <= 1) { /* error launching udev */
    return;
  }

  forkexecwait(info_argv);
  forkexecwait(control_argv);

} /*}}}*/

static int switch_root(char *argv[]) { /* {{{ */
  struct stat st;
  struct statfs stfs;
  dev_t rootdev;

  /* this is mostly taken from busybox's util_linux/switch_root.c */

  chdir(NEWROOT);
  stat("/", &st);
  rootdev = st.st_dev;

  /* sanity checks: we're about to rm -rf / ! */
  if (stat("/init", &st) != 0 || !S_ISREG(st.st_mode)) {
    die("/init not found or not a regular file\n");
  }

  statfs("/", &stfs); /* this never fails */
  if ((unsigned)stfs.f_type != RAMFS_MAGIC &&
      (unsigned)stfs.f_type != TMPFS_MAGIC) {
    die("root filesystem is not ramfs/tmpfs!\n");
  }

  /* zap everything out of rootdev */
  delete_contents("/", rootdev);

  /* mount $PWD over / and chroot into it */
  if (mount(".", "/", NULL, MS_MOVE, NULL) != 0) {
    /* fails when newroot is not a mountpoint */
    die("error moving root\n");
  }
  chroot(".");

  /* The chdir is needed to recalculate "." and ".." links */
  chdir("/");

  /* redirect stdin/stdout/stderr to new console */
  close(STDIN_FILENO);
  open("/dev/console", O_RDWR);
  dup2(STDIN_FILENO, STDOUT_FILENO);
  dup2(STDIN_FILENO, STDERR_FILENO);

  /* exec real pid shady */
  execv(argv[0], argv);
  err("failed to execute '%s'\n", argv[0]);
  fprintf(stderr, ":: This is the end. Something has gone terribly wrong.\n"
                  ":: Please file a detailed bug report.\n");
  exit(EXIT_FAILURE);
} /* }}} */

int main(int argc, char *argv[]) {
  pid_t udevpid;

  (void)argc; /* poor unloved argc */

  mount_setup();                /* create early tmpfs mountpoints */
  put_cmdline();                /* parse cmdline and set environment */
  disable_modules();            /* blacklist modules passed in on cmdline */
  udevpid = launch_udev();      /* try to launch udev */
  load_extra_modules();         /* load modules passed in on cmdline */
  trigger_udev_events();        /* read and process uevent queue */
  disable_hooks();              /* delete hooks specified on cmdline */
  run_hooks();                  /* run remaining hooks */
  check_for_break();            /* did the user request a shell? */

  if (wait_for_root() != 0) {
    try_create_root();          /* ensure that root shows up */
  }

  if (mount_root() != 0) {      /* this is what we're here for */
    err("failed to mount the root device: %s\n", strerror(errno));
    start_rescue_shell();
  }

  if (set_init() != 0) {        /* mounted something, now find init */
    err("root device was mounted, but %s does not exist!\n", getenv("init"));
    start_rescue_shell();
  }

  kill_udev(udevpid);           /* shutdown udev in prep switch_root  */

  /* migrate to the new root */
  movemount("/proc", NEWROOT "/proc");
  movemount("/sys", NEWROOT "/sys");
  movemount("/run", NEWROOT "/run");

  argv[0] = getenv("init");
  switch_root(argv);
  /* unreached */
  return 0;
}

/* vim: set et ts=2 sw=2 */
