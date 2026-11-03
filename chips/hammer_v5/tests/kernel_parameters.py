"""Compile the actual pinned/patched parameter helpers against observed sysfs APIs.

This host fixture covers batching semantics, not genuine kernel execution.
Linux/userland acceptance still requires both complete RTL boots.
"""
import importlib.util
import json
import tarfile

from evidence import ROOT, digest


STUBS = r"""
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#define __init
#define __modinit
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define MODULE_NAME_LEN 64
#define KOBJ_ADD 1
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define to_module_kobject(p) container_of(p,struct module_kobject,kobj)
#define to_param_attr(p) container_of(p,struct param_attribute,mattr)
#define BUG_ON(c) do {if(c) {fprintf(stderr,"KERNEL BUG fixture\n");exit(2);}} while(0)
#define CHECK(c,m) do {if(!(c)) {fprintf(stderr,"PARAMETER CHECK: %s\n",m);exit(1);}} while(0)
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(name) struct list_head name={&name,&name}
static void list_add_tail(struct list_head *n,struct list_head *h) {
 n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;
}
static void list_del(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;}
#define entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for(p=entry((h)->next,__typeof__(*p),m);&p->m!=(h);p=entry(p->m.next,__typeof__(*p),m))
#define list_for_each_entry_safe(p,n,h,m) \
 for(p=entry((h)->next,__typeof__(*p),m),n=entry(p->m.next,__typeof__(*p),m); \
 &p->m!=(h);p=n,n=entry(n->m.next,__typeof__(*n),m))
struct module {int unused;};
struct kernel_param;
struct kernel_param_ops {
 int (*get)(char *,const struct kernel_param *);
 int (*set)(const char *,const struct kernel_param *);
};
struct kernel_param {
 const char *name;unsigned perm;const struct kernel_param_ops *ops;int *arg;unsigned flags;
};
struct attribute {char *name;unsigned mode;};
struct attribute_group {const char *name;struct attribute **attrs;};
struct module_kobject;
struct module_attribute {
 struct attribute attr;
 ssize_t (*show)(struct module_attribute *,struct module_kobject *,char *);
 ssize_t (*store)(struct module_attribute *,struct module_kobject *,const char *,size_t);
};
struct kobject {char name[64];void *kset;unsigned references,published,events;};
struct module_param_attrs;
struct module_kobject {struct kobject kobj;struct module *mod;struct module_param_attrs *mp;};
static struct module_kobject *objects[8];static unsigned object_count;
static void *module_kset;static int module_ktype,locked,temporary_groups,publications;
static void *allocate_zero(size_t,int,const char *);
#define kzalloc(s,f) allocate_zero(s,f,__func__)
static void *krealloc(void *,size_t,int);
static void kfree(void *);
static unsigned lookup_count;
static void kernel_param_lock(struct module *m) {CHECK(!locked,"recursive lock");locked=1;}
static void kernel_param_unlock(struct module *m) {CHECK(locked,"unlock");locked=0;}
static int param_check_unsafe(const struct kernel_param *p) {
 CHECK(locked,"unsafe check lock");return !p->flags;
}
static int get_value(char *buf,const struct kernel_param *p) {
 CHECK(locked,"get callback lock");return sprintf(buf,"%d\n",*p->arg);
}
static int set_value(const char *buf,const struct kernel_param *p) {
 CHECK(locked,"set callback lock");*p->arg=atoi(buf);return 0;
}
static int get_error(char *buf,const struct kernel_param *p) {return -EIO;}
static int set_error(const char *buf,const struct kernel_param *p) {return -EINVAL;}
static const struct kernel_param_ops rw={get_value,set_value},wo={NULL,set_value},
 no_set={get_value,NULL},errors={get_error,set_error};
static int values[]={7,11,23,99,17,31,37,41,43};
static struct kernel_param fixture[]={
 {"alpha.first",0644,&rw,&values[0],0},{"core",0644,&rw,&values[1],0},
 {"beta.readonly",0444,&rw,&values[2],0},{"hidden.secret",0,&rw,&values[3],0},
 {"kernel.explicit",0600,&rw,&values[4],0},{"alpha.second",0200,&wo,&values[5],0},
 {"beta.no_set",0644,&no_set,&values[6],0},
 {"alpha.callback_error",0644,&errors,&values[7],0},
 {"beta.unsafe",0644,&rw,&values[8],1}
};
#define __start___param fixture
#define __stop___param (fixture+sizeof(fixture)/sizeof(fixture[0]))
static const char *kobject_name(const struct kobject *k) {return k->name;}
static struct kobject *kobject_get(struct kobject *k) {k->references++;return k;}
static void kobject_put(struct kobject *k) {CHECK(k->references>1,"reference lifetime");k->references--;}
static struct kobject *kset_find_obj(void *s,const char *name) {
 lookup_count++;
 for(unsigned i=0;i<object_count;i++)
  if(!strcmp(objects[i]->kobj.name,name)) return kobject_get(&objects[i]->kobj);
 return NULL;
}
static int kobject_init_and_add(struct kobject *k,int *type,void *parent,
                                 const char *format,const char *name) {
 CHECK(object_count<8,"object bound");snprintf(k->name,sizeof(k->name),"%s",name);
 k->references=1;objects[object_count++]=to_module_kobject(k);return 0;
}
static void pr_crit(const char *format,const char *name,int err) {
 fprintf(stderr,format,name,err);exit(3);
}
static ssize_t strscpy(char *out,const char *in,size_t size) {
 size_t n=strnlen(in,size-1);memcpy(out,in,n);out[n]=0;return n;
}
static void sysfs_attr_init(struct attribute *a) {}
static int sysfs_create_group(struct kobject *,const struct attribute_group *);
static void kobject_uevent(struct kobject *k,int event) {
 CHECK(k->published==1 && !k->events && event==KOBJ_ADD,"one completed group event");
 k->events++;
}
__KERNEL_HELPERS__
static size_t allocation_size[128];static void *allocations[128];static int allocation_group[128];
static void *allocate_zero(size_t size,int flags,const char *caller) {
 void *p=calloc(1,size);CHECK(p,"host allocation");
 for(unsigned i=0;i<128;i++) if(!allocations[i]) {
  allocations[i]=p;allocation_size[i]=size;
  allocation_group[i]=!strcmp(caller,"kernel_add_sysfs_param");
  if(allocation_group[i]) temporary_groups++;
  return p;
 }
 CHECK(0,"allocation bound");return NULL;
}
static void kfree(void *p) {
 if(!p) return;
 for(unsigned i=0;i<128;i++) if(allocations[i]==p) {
  if(allocation_group[i]) temporary_groups--;
  allocations[i]=NULL;free(p);return;
 }
 CHECK(0,"free ownership");
}
static void *krealloc(void *old,size_t size,int flags) {
 for(unsigned i=0;i<128;i++) if(allocations[i]==old) {
  size_t prior=allocation_size[i];void *p=kzalloc(size,0);
  memcpy(p,old,prior<size?prior:size);kfree(old);return p;
 }
 CHECK(0,"reallocation ownership");return NULL;
}
static const unsigned expected_ids[3][3]={{0,5,7},{1,4,0},{2,6,8}};
static const char *expected_groups[]={"alpha","kernel","beta"};
static const unsigned expected_counts[]={3,2,3};
static unsigned attribute_checks,callback_checks;
static int sysfs_create_group(struct kobject *k,const struct attribute_group *group) {
 struct module_kobject *mk=to_module_kobject(k);
 CHECK(publications<3 && !strcmp(k->name,expected_groups[publications]),
       "group/attribute publication order");
 CHECK(!k->published && k->references==2,"group reference before publication");
 CHECK(!strcmp(group->name,"parameters") && mk->mp->num==expected_counts[publications],
       "group/attribute completeness");
 for(unsigned i=0;i<expected_counts[publications];i++) {
  const struct kernel_param *parameter=&fixture[expected_ids[publications][i]];
  const char *dot=strchr(parameter->name,'.'),*name=dot?dot+1:parameter->name;
  CHECK(group->attrs[i]==&mk->mp->attrs[i].mattr.attr,"relocated attribute pointers");
  CHECK(!strcmp(group->attrs[i]->name,name) && group->attrs[i]->mode==parameter->perm &&
        mk->mp->attrs[i].param==parameter,"group/attribute names, modes, backing values");
  CHECK(!!mk->mp->attrs[i].mattr.store==!!(parameter->perm&0222),
        "read-only store callback protection");
  attribute_checks++;
 }
 CHECK(!group->attrs[mk->mp->num],"attribute terminator");
 k->published++;publications++;return 0;
}
int main(void) {
 struct module_kobject existing={0};
 strcpy(existing.kobj.name,"beta");existing.kobj.references=1;objects[object_count++]=&existing;
 param_sysfs_builtin();
 CHECK(publications==3 && lookup_count==3 && object_count==3 && !temporary_groups,
       "group lookup and temporary reference lifetime");
 for(unsigned o=0;o<object_count;o++) {
  struct module_kobject *mk=objects[o];
  CHECK(mk->kobj.references==1 && mk->kobj.events==1 && mk->kobj.published==1,
        "final object reference lifetime");
  for(unsigned i=0;i<mk->mp->num;i++) {
   struct module_attribute *attribute=&mk->mp->attrs[i].mattr;
   const struct kernel_param *p=mk->mp->attrs[i].param;
   char text[32],expected[32];sprintf(expected,"%d\n",*p->arg);
   ssize_t got=attribute->show(attribute,mk,text);
   if(p->ops==&errors) CHECK(got==-EIO,"getter error propagation");
   else if(!p->ops->get) CHECK(got==-EPERM,"missing getter rejection");
   else CHECK(got==(ssize_t)strlen(expected) && !strcmp(text,expected),"getter value");
   callback_checks++;
   int previous=*p->arg;
   if(!(p->perm&0222)) {
    CHECK(!attribute->store,"read-only write rejection");continue;
   }
   got=attribute->store(attribute,mk,"57",2);
   if(p->ops==&errors) CHECK(got==-EINVAL && *p->arg==previous,"setter error propagation");
   else if(!p->ops->set || p->flags)
    CHECK(got==-EPERM && *p->arg==previous,"unsafe/missing setter rejection");
   else CHECK(got==2 && *p->arg==57,"setter result and backing value");
   callback_checks++;
  }
 }
 CHECK(!locked && values[3]==99 && values[2]==23,"hidden/read-only/locking preservation");
 printf("SUMMARY kernel-parameters groups=%d attributes=%u callbacks=%u\n",
        publications,attribute_checks,callback_checks);
 return 0;
}
"""


def parameter_source(ev):
    manifest = json.loads((ROOT / "software/boot_manifest.json").read_text())
    linux, = (source for source in manifest["sources"] if source["version"] == "6.6.1")
    archive = ROOT / "software" / linux["file"]
    if digest(archive) != linux["sha256"]:
        raise AssertionError("parameter fixture pinned Linux checksum mismatch")
    with tarfile.open(archive, "r:xz") as source:
        stream = source.extractfile(linux["root"] + "/kernel/params.c")
        if stream is None:
            raise AssertionError("pinned kernel parameter source missing")
        text = stream.read().decode()
    directory = ev.directory / ("kernel-parameters-" + linux["sha256"][:16])
    (directory / "kernel").mkdir(parents=True)
    path = directory / "kernel/params.c"
    path.write_text(text)
    specification = importlib.util.spec_from_file_location(
        "hammer_parameter_patch", ROOT / "software/patch_sources.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    module.batch_builtin_parameters(directory)
    patched = path.read_text()
    sections = (
        ("struct param_attribute\n", "#ifdef CONFIG_SYSFS"),
        ("static ssize_t param_attr_show", "#endif"),
        ("static __modinit int add_sysfs_param", "#ifdef CONFIG_MODULES"),
        ("static struct module_kobject * __init locate_module_kobject",
         "ssize_t __modver_version_show"),
    )
    helpers = []
    for start, stop in sections:
        begin = patched.index(start)
        helpers.append(patched[begin:patched.index(stop, begin)])
    for generated in (path,):
        ev.record.setdefault("generated_sha256", {})[ev.relative(generated)] = digest(generated)
    return STUBS.replace("__KERNEL_HELPERS__", "\n".join(helpers))


def kernel_parameters_probe(ev):
    baseline = parameter_source(ev)
    observations = []
    cases = (
        ("baseline", None, None, None),
        ("core-grouping", 'strcpy(modname, "kernel")',
         'strcpy(modname, "core")', "group/attribute"),
        ("attribute-name", "kparam->name + name_skip", "kparam->name", "group/attribute"),
        ("early-publication", "err = add_sysfs_param(mk, kparam, kparam->name + name_skip);",
         "err = add_sysfs_param(mk, kparam, kparam->name + name_skip);\n"
         "sysfs_create_group(&mk->kobj, &mk->mp->grp);", "group/attribute"),
        ("reference-leak", "kobject_put(&mk->kobj);\n\t\tlist_del", "list_del",
         "final object reference lifetime"),
    )
    for name, old, new, diagnostic in cases:
        text = baseline
        if old is not None:
            if text.count(old) != 1:
                raise AssertionError("kernel parameter defect anchor missing/ambiguous")
            text = text.replace(old, new)
        path = ev.directory / ("kernel-parameters-" + name + ".c")
        path.write_text(text)
        ev.record.setdefault("generated_sha256", {})[ev.relative(path)] = digest(path)
        binary = ev.directory / ("kernel-parameters-" + name)
        ev.run(["g++", "-x", "c", "-std=gnu11", "-O2", "-Wall", "-Wextra",
                "-Werror", "-Wno-unused-parameter", path.name, "-o", binary.name],
               "kernel-parameters-" + name + "-compile", cwd=ev.directory)
        try:
            output = ev.run(["./" + binary.name], "kernel-parameters-" + name + "-run",
                            cwd=ev.directory, expected_exit=0 if old is None else 1)
            if old is None:
                if "SUMMARY kernel-parameters groups=3 attributes=8 callbacks=15" not in output:
                    raise AssertionError("kernel parameter baseline comparisons incomplete")
            elif diagnostic not in (ROOT / ev.record["commands"][-1]["stderr"]).read_text():
                raise AssertionError("kernel parameter mutant rejected for wrong reason")
            observations.append({"case": name, "compiled_and_executed": True,
                                 "expected_rejection": diagnostic})
        finally:
            if binary.is_file():
                binary.unlink()
    ev.record["kernel_parameter_host_checks"] = {
        "actual_patched_helpers": True, "not_RTL_or_full_kernel_execution": True,
        "noncontiguous_groups": True, "core_and_explicit_kernel_shared": True,
        "forced_relocation": True, "observations": observations}
    ev.save()
