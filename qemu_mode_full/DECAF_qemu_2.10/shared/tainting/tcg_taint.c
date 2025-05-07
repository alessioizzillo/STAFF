#include "qemu/osdep.h"
#include "cpu.h"

#include "qemu-common.h"

#ifdef CONFIG_TCG_TAINT

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>

#include "tcg.h"
#include "tainting/tcg_taint.h"

#include "tainting/taint_memory.h"
#include "config-target.h"

// #include "helper.h" // Taint helper functions, plus I386 IN/OUT helpers
#include "DECAF_callback_common.h"
#include "DECAF_callback_to_QEMU.h"

#include "exec/helper-gen.h"
#include "exec/helper-head.h"
#include "extern_vars.h"

typedef struct TCGHelperInfo {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
} TCGHelperInfo;

TCGHelperInfo debug_helper;

void helper_taint_debug(target_ulong arg) {
  if (debug_taint) {
    FILE *fp = fopen("debug/taint.log","a+");
    fprintf(fp, "VAL = 0x%lx\n", arg);
    fclose(fp);
  }
}

static inline void gen_helper_debug_taint(TCGArg arg1) {
  static int add = 0;

  if (!add) {
    debug_helper.func = helper_taint_debug;
    debug_helper.name = "taint_debug";
    debug_helper.flags = 0;
    debug_helper.sizemask = dh_sizemask(void, 0) | dh_sizemask(tl, 1);
    g_hash_table_insert(tcg_ctx.helpers, (gpointer)debug_helper.func, (gpointer)&debug_helper);    
    add = 1;
  }

  TCGArg args[1] = { arg1 };
  tcg_gen_callN(&tcg_ctx, helper_taint_debug, dh_retvar(void), 1, args);  
}

TCGArg *gen_opparam_ptr;
TCGOp *gen_op_ptr;
int skip_taint_right_shift_amount = 0;
int skip_taint_left_shift_amount = 0;

// Typedef the CPU state struct to make tempidx ld/st cleaner
#if defined(TARGET_I386)
typedef CPUX86State OurCPUState;
#elif defined(TARGET_ARM)
typedef CPUARMState OurCPUState;
#elif defined(TARGET_MIPS)
typedef CPUMIPSState OurCPUState;
#endif /* TARGET_I386/ARM */

// AWH - Declare variables specific to this arch's helper funcs
#define HELPER_SECTION_ONE
#include "helper_arch_check.h"

// AWH - In development
//#define USE_TCG_OPTIMIZATIONS 1
#define LOG_TAINTED_EIP
// AWH - Change these to change taint/pointer rules
// #define TAINT_EXPENSIVE_ADDSUB 1
// #define TCG_BITWISE_TAINT 1
//#define TAINT_NEW_POINTER 1
// #define DUMMY_TAINT_FOR_64BIT 1

#if defined(LOG_TAINTED_EIP)
#define MAX_TAINT_LOG_TEMPS 10
static TCGArg helper_arg_array[MAX_TAINT_LOG_TEMPS];
static TCGv taint_log_temps[MAX_TAINT_LOG_TEMPS];
static inline void set_con_i32(int index, TCGv arg)
{
	  tcg_gen_mov_i32(taint_log_temps[index], arg);
	  helper_arg_array[index] = taint_log_temps[index];
}

#endif

// Exposed externs
TCGv shadow_arg[TCG_MAX_TEMPS];
TCGv tempidx, tempidx2;
extern int call_taint = 0;

// // Extern in translate.c
// TCGv_ptr cpu_env;

/* Find helper name.  */
static inline const char *tcg_find_helper(TCGContext *s, uintptr_t val)
{
    const char *ret = NULL;
    if (s->helpers) {
        TCGHelperInfo *info = g_hash_table_lookup(s->helpers, (gpointer)val);
        if (info) {
            ret = info->name;
        }
    }
    return ret;
}

static inline int temp_idx(TCGContext *s, TCGTemp *ts)
{
    ptrdiff_t n = ts - s->temps;
    if (!global_taint_flag)
      tcg_debug_assert(n >= 0 && n < s->nb_temps);
    else
      tcg_debug_assert(n >= 0 && n < s->nb_temps2);      
    return n;
}

static char *tcg_get_arg_str_ptr(TCGContext *s, char *buf, int buf_size,
                                 TCGTemp *ts)
{
    int idx = temp_idx(s, ts);

    if (idx < s->nb_globals) {
        pstrcpy(buf, buf_size, ts->name);
    } else if (ts->temp_local) {
        snprintf(buf, buf_size, "loc%d", idx - s->nb_globals);
    } else {
        snprintf(buf, buf_size, "tmp%d", idx - s->nb_globals);
    }
    return buf;
}

static char *tcg_get_arg_str_idx(TCGContext *s, char *buf,
                                 int buf_size, int idx)
{   
    if (!global_taint_flag)
      tcg_debug_assert(idx >= 0 && idx < s->nb_temps);
    else
      tcg_debug_assert(idx >= 0 && idx < s->nb_temps2);    
    return tcg_get_arg_str_ptr(s, buf, buf_size, &s->temps[idx]);
}

/*static*/ TCGv find_shadow_arg(TCGv arg)
{
//   if (arg < tcg_ctx.nb_globals)
//     return shadow_arg[arg];

//   /* Check if this temp is allocated in the context */
//   if (!tcg_ctx.temps[arg].temp_allocated)
//     return 0;

//   if (!tcg_ctx.temps[shadow_arg[arg]].temp_allocated) {
//     if (tcg_ctx.temps[arg].temp_local)
// #if TCG_TARGET_REG_BITS == 32
//       shadow_arg[arg] = tcg_temp_local_new_i32();
//     else
//       shadow_arg[arg] = tcg_temp_new_i32();
// #else
//       shadow_arg[arg] = tcg_temp_local_new_i64();
//     else
//       shadow_arg[arg] = tcg_temp_new_i64();
// #endif
//     // CLEAR TAINT ON CREATION
//     tcg_ctx.temps[shadow_arg[arg]].val = 0;
//   }

  return shadow_arg[arg];
}

void clean_shadow_arg(void)
{
  bzero(&shadow_arg[tcg_ctx.nb_globals], sizeof(shadow_arg[0]) * (TCG_MAX_TEMPS - tcg_ctx.nb_globals));
}

/* AWH - Dummy generic taint rule to make sure we have the proper
   shadow taint temps in place */
static void DUMMY_TAINT(int nb_oargs, int nb_args)
{
  //zyw
  TCGArg *gen_opparam_ptr = tcg_ctx.gen_opparam_buf;
  TCGv arg0, orig0;

  int i = 0;
  for (i = 0; i < nb_oargs; i++)
  {
    arg0 = find_shadow_arg(gen_opparam_ptr[(-1 * nb_args) + i]);
    orig0 = gen_opparam_ptr[(-1 * nb_args) + i];
    if (arg0) {
#if TCG_TARGET_REG_BITS == 32
      tcg_gen_movi_i32(arg0, 0);
#else
      tcg_gen_movi_i64(arg0, 0);
#endif
    }
  }
}

int add_orig(TCGOp *op, TCGArg *opparam_ptr, int nb_args)
{
  int args = tcg_ctx.gen_next_parm_idx;
  int i;

  if (op->opc) {
    for(i=0; i<nb_args; i++) {
      memcpy(&tcg_ctx.gen_opparam_buf[tcg_ctx.gen_next_parm_idx], &opparam_ptr[i-nb_args], sizeof(TCGArg));
      tcg_ctx.gen_next_parm_idx++;
    }
  }

  int oi = tcg_ctx.gen_next_op_idx;
  int ni = oi + 1;
  int pi = oi ? (oi - 1) : 0;

  tcg_debug_assert(oi < OPC_BUF_SIZE);
  tcg_ctx.gen_op_buf[0].prev = oi;
  tcg_ctx.gen_next_op_idx = ni;

  tcg_ctx.gen_op_buf[oi] = (TCGOp){
      .opc = op->opc,
      .prev = pi,
      .next = ni,
      .calli = op->calli,
      .callo = op->callo,
      .args = args,
      .life = op->life
  };
}

#ifdef CONFIG_2nd_CCACHE

int check(TCGOp *old_op_buf, TCGArg *old_param_buf) {
  int num_op = tcg_ctx.gen_next_op_idx;
  int num_parm = tcg_ctx.gen_next_parm_idx;

  int i;

  for (i = 0; i < num_op; i++) {
    if (memcmp(&old_op_buf[i], &tcg_ctx.gen_op_buf[i], sizeof(TCGOp)))
      return 0;
  } 

  for (i = 0; i < num_parm; i++) {
    if (memcmp(&old_param_buf[i], &tcg_ctx.gen_opparam_buf[i], sizeof(TCGArg)))
      return 0;
  }

  return 1;
}

int gen_taintcheck_insn_ld() ///sina: This function instruments only Qemu load for the no-overhead code cache
{
  global_taint_flag = 1;

#ifdef CONFIG_TCG_TAINT
  /* Opcode and parameter buffers */
  static TCGOp gen_old_op_buf[OPC_BUF_SIZE];
  static TCGArg gen_old_opparam_buf[OPPARAM_BUF_SIZE];

  int num_op = tcg_ctx.gen_next_op_idx;
  int num_parm = tcg_ctx.gen_next_parm_idx;
  int return_lj = -1;

  int nb_args=0;
  op_index=0;
  int i=0;
  TCGOpcode opc=0;
  int nb_oargs=0, nb_iargs=0, nb_cargs=0;
  TCGv arg0, arg1, arg2, arg3, arg4, arg5;
  TCGv t0, t1, t2, t3, t4, t_zero;
#if defined(TARGET_I386)
  TCGv arg6, t5, t6;
#endif /* TARGET check */
  TCGv orig0, orig1, orig2, orig3, orig4, orig5;

  gen_op_ptr = tcg_ctx.gen_op_buf;
  gen_opparam_ptr = tcg_ctx.gen_opparam_buf;

  /* Copy and instrument the opcodes that need taint tracking */
  while(op_index < num_op) {
    /* Copy the op and the appropriate number of arguments for the opcode */
    gen_op_ptr++;
    op_index++;

    /* Copy the opcode to be instrumented */
    opc = gen_op_ptr[-1].opc;

    /* Determine the number and type of arguments for the opcode */
    if (opc == INDEX_op_call) {
      nb_oargs = gen_op_ptr[-1].callo;
      nb_iargs = gen_op_ptr[-1].calli;
      nb_cargs = tcg_op_defs[opc].nb_cargs;
      nb_args = nb_oargs + nb_iargs + 2; // N out args + N in args + (1) func + (1) flags (take a look at tcg_gen_callN())
    } else {
      nb_args = tcg_op_defs[opc].nb_args;
      nb_oargs = tcg_op_defs[opc].nb_oargs;
      nb_iargs = tcg_op_defs[opc].nb_iargs;
      nb_cargs = tcg_op_defs[opc].nb_cargs;
    }

    gen_opparam_ptr = tcg_ctx.gen_opparam_buf + gen_op_ptr[-1].args + nb_args;

    switch(opc)
    {
      /* Load/store operations (32 bit). */
      /* MemCheck: mkLazyN() (Just load/store taint from/to memory) */
      case INDEX_op_qemu_ld_i32:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        // TARGET_REG_BITS = 64 OR (TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32)
        if (nb_iargs == 1) arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 64
        else tcg_abort(); // Not supported

        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);

          if (arg1) {
#if (TCG_TARGET_REG_BITS == 64)
            t0 = tcg_temp_new_i64();
            t1 = tcg_temp_new_i64();
            t2 = tcg_temp_new_i64();
            t3 = tcg_temp_new_i64();

#if defined(TARGET_MIPS)
            /* Load taint from tempidx */
            tcg_gen_ld32u_tl(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

#ifndef TAINT_NEW_POINTER //more selective pointer tainting
            t_zero = tcg_temp_new_i64();
            tcg_gen_movi_i64(t_zero, 0);

            tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t_zero);
            tcg_temp_free_i64(t_zero);
#else
            t4 = tcg_temp_new_i64();
            tcg_gen_movi_i64(t2, 0xffff0000);
            tcg_gen_and_i64(t0, arg1, t2);//t0 = H_taint
            tcg_gen_movi_i64(t2, 0);
            tcg_gen_setcond_i64(TCG_COND_EQ, t1, t0, t2);  //t1=(H_taint==0) cond1

            tcg_gen_setcond_i64(TCG_COND_NE, t4, arg1, t2);  //t4=(P_taint!=0) cond2
            tcg_gen_and_i64(t2, t1, t4); //t2 = cond1 & cond2
            tcg_temp_free_i64(t4);
#endif
            tcg_gen_neg_i64(t0, t2);

            /* Combine pointer and tempidx taint */
            // tcg_gen_or_i64(arg0, t0, t3);  // Overtaint
            tcg_gen_mov_i64(arg0, t3);

            tcg_temp_free_i64(t0);
            tcg_temp_free_i64(t1);
            tcg_temp_free_i64(t2);
            tcg_temp_free_i64(t3);
#else
            t0 = tcg_temp_new_i32();
            t1 = tcg_temp_new_i32();
            t2 = tcg_temp_new_i32();
            t3 = tcg_temp_new_i32();

#if defined(TARGET_MIPS)
            /* Load taint from tempidx */
            tcg_gen_ld_i32(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

#ifndef TAINT_NEW_POINTER
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);

            tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t_zero);
            tcg_temp_free_i32(t_zero);
#else
            t4 = tcg_temp_new_i32();
            tcg_gen_movi_i32(t2, 0xffff0000); //??
            tcg_gen_and_i32(t0, arg1, t2);//t0 = H_taint
            tcg_gen_movi_i32(t2, 0);
            tcg_gen_setcond_i32(TCG_COND_EQ, t1, t0, t2);  //t1=(H_taint==0) cond1

            tcg_gen_setcond_i32(TCG_COND_NE, t4, arg1, t2);  //t4=(P_taint!=0) cond2
            tcg_gen_and_i32(t2, t1, t4); //t2 = cond1 & cond2
            tcg_temp_free_i32(t4);
#endif
            tcg_gen_neg_i32(t0, t2);
            /* Combine pointer and tempidx taint */
            // tcg_gen_or_i32(arg0, t0, t3);  // Overtaint
            tcg_gen_mov_i32(arg0, t3);

            tcg_temp_free_i32(t0);
            tcg_temp_free_i32(t1);
            tcg_temp_free_i32(t2);
            tcg_temp_free_i32(t3);
#endif /* TARGET_REG_BITS */

          } else {
#if defined(TARGET_MIPS)
            /* Patch in opcode to load taint from tempidx */
            tcg_gen_ld_i32(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
          }
        }
        break;

      case INDEX_op_qemu_ld_i64:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

#ifdef DUMMY_TAINT_FOR_64BIT // AWH - FIXME: 64-bit memory ops may cause corruption
        DUMMY_TAINT(nb_oargs, nb_args);
#else
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32
        if ((nb_oargs == 2) && (nb_iargs == 1)) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Taint of low DWORD
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Taint of hi DWORD
          if (arg0 || arg1) {
            arg2 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg2) {
              t0 = tcg_temp_new_i32();
              t1 = tcg_temp_new_i32();
              t2 = tcg_temp_new_i32();
              t3 = tcg_temp_new_i32();

#if defined(TARGET_MIPS)
              /* Load taint from tempidx */
              tcg_gen_ld_i32(t2, cpu_env, offsetof(OurCPUState,tempidx));
              tcg_gen_ld_i32(t3, cpu_env, offsetof(OurCPUState, tempidx2));
#endif

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i32();
              tcg_gen_movi_i32(t_zero, 0);

              tcg_gen_setcond_i32(TCG_COND_NE, t1, arg2, t_zero);
              tcg_gen_neg_i32(t0, t1);

              /* Combine pointer and tempidx taint */
              if (arg0) {
                // tcg_gen_or_i32(arg0, t0, t2);  // Overtaint
                tcg_gen_mov_i32(arg0, t2);
              }
              if (arg1) {
                // tcg_gen_or_i32(arg1, t0, t3);  // Overtaint
                tcg_gen_mov_i32(arg1, t3);
              }

              tcg_temp_free_i32(t_zero);
              tcg_temp_free_i32(t0);
              tcg_temp_free_i32(t1);
              tcg_temp_free_i32(t2);
              tcg_temp_free_i32(t3);                

            } else {
#if defined(TARGET_MIPS)
              /* Patch in opcode to load taint from tempidx */
              if (arg0) {
                tcg_gen_ld_i32(arg0, cpu_env, offsetof(OurCPUState,tempidx));
              }
              if (arg1) {
                tcg_gen_ld_i32(arg1, cpu_env, offsetof(OurCPUState,tempidx2));
              }
#endif
            }
          }
        // TARGET_REG_BITS = 64, TARGET_LONG_BITS = 64
        } else if ((nb_oargs ==1) && (nb_iargs == 1)) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
          if (arg0) {
            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg1) {
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();
              t3 = tcg_temp_new_i64();

#if defined(TARGET_MIPS)
              /* Load taint from tempidx */
              tcg_gen_ld_i64(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i64();
              tcg_gen_movi_i64(t_zero, 0);

              tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t_zero);
              tcg_gen_neg_i64(t0, t2);

              /* Combine pointer and tempidx taint */
              // tcg_gen_or_i64(arg0, t0, t3);  // Overtaint
              tcg_gen_mov_i64(arg0, t3);

              tcg_temp_free_i64(t_zero);
              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
              tcg_temp_free_i64(t3);
            } else {
#if defined(TARGET_MIPS)
              /* Patch in opcode to load taint from tempidx */
              tcg_gen_ld_i64(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
            }
          }
        // TARGET_REG_BITS = 64, TARGET_LONG_BITS = 32
        } else
          tcg_abort();
#endif // FIXME
        break;

      case INDEX_op_qemu_st_i32:
qemu_st_i32:
        // TARGET_REG_BITS = 64 OR (TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32)
        if (nb_iargs == 2 || call_taint) {
          arg0 = call_taint ? find_shadow_arg(gen_opparam_ptr[-5]) : find_shadow_arg(gen_opparam_ptr[-3]);
          
          if (!call_taint)
            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);

          if (arg0) {
            /* Save the qemu_st* parameters */
            int mem_index = gen_opparam_ptr[-1];
            int addr = gen_opparam_ptr[-2];
            int ret = gen_opparam_ptr[-3];
            int ir = gen_op_ptr[-1].opc;

            if (arg1) {

#if (TCG_TARGET_REG_BITS == 64)
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i64();
              tcg_gen_movi_i64(t_zero, 0);
              tcg_gen_movi_i64(t0, 0);
              tcg_gen_movi_i64(t2, 0);

              if (!call_taint) {
                tcg_gen_setcond_i64(TCG_COND_NE, t2, arg0, t_zero);
                tcg_gen_neg_i64(t0, t2);
              }

              /* Combine pointer and data taint */
              // tcg_gen_or_i64(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i64(t1, arg0);
#if defined(TARGET_MIPS)
              /* Store combined taint to tempidx */
              tcg_gen_st32_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
#endif

              tcg_temp_free_i64(t_zero);
              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
#else
              t0 = tcg_temp_new_i32();
              t1 = tcg_temp_new_i32();
              t2 = tcg_temp_new_i32();

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i32();
              tcg_gen_movi_i32(t_zero, 0);
              tcg_gen_movi_i32(t0, 0);
              tcg_gen_movi_i32(t2, 0);

              if (!call_taint) {
                tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t_zero);
                tcg_gen_neg_i32(t0, t2);
              }

              /* Combine pointer and data taint */
              // tcg_gen_or_i32(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i32(t1, arg0);
#if defined(TARGET_MIPS)
              /* Store combined taint to tempidx */
              tcg_gen_st32_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
#endif
              tcg_temp_free_i32(t_zero);
              tcg_temp_free_i32(t0);
              tcg_temp_free_i32(t1);
              tcg_temp_free_i32(t2);
#endif /* TARGET_REG_BITS */

            } else {
#if defined(TARGET_MIPS)
              tcg_gen_st32_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
            }
          }
        } else
          tcg_abort();

        call_taint = 0;
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_qemu_st_i64:
#if defined(TARGET_MIPS)
        /* TARGET_REG_BITS == 64 */
        if (nb_iargs == 2) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
          if (arg0) {
            /* Save the qemu_st64 parameters */
            int mem_index = gen_opparam_ptr[-1];
            int addr = gen_opparam_ptr[-2];
            int ret = gen_opparam_ptr[-3];

            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg1) {
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();

              /* Check for pointer taint */
              tcg_gen_movi_i64(t1, 0);

              tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t1);
              tcg_gen_neg_i64(t0, t2);

              /* Combine pointer and data taint */
              // tcg_gen_or_i64(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i64(t1, arg0);
              /* Store combined taint to tempidx */
              tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));

              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
            } else {
              tcg_gen_st_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
            }

          }
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32
        } else if (nb_iargs == 3) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Taint of low DWORD
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Taint of high DWORD
          if (arg0 || arg1) {
            int ret_lo = gen_opparam_ptr[-4]; // Low DWORD of data
            int ret_hi = gen_opparam_ptr[-3]; // High DWORD of Data
            int addr = gen_opparam_ptr[-2]; // Addr
            int mem_index = gen_opparam_ptr[-1]; // MMU index

            t0 = tcg_temp_new_i32();
            t1 = tcg_temp_new_i32();
            t2 = tcg_temp_new_i32();
            arg2 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg2) {
              /* Check for pointer taint */
              tcg_gen_movi_i32(t1, 0);

              tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t1);
              tcg_gen_neg_i32(t0, t2);
              /* Combine pointer and data taint */
              if (!arg0) {
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx));
              }
              else {
                // tcg_gen_or_i32(t1, t0, arg0);  // Overtaint
                tcg_gen_mov_i32(t1, arg0);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
              }

              if (!arg1) {
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx2));
              }
              else {
                // tcg_gen_or_i32(t1, t0, arg1);  // Overtaint
                tcg_gen_mov_i32(t1, arg1);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx2));
              }

            } else {
              /* If there is no shadow data for either one of the 32-bit chunks
              that make up this 64-bit store, then use a zeroed-out temp reg
              to indicate there is no taint for that 32-bit chunk. */
              if (!arg0) {
                tcg_gen_movi_i32(t0, 0);
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx));
              } else {
                tcg_gen_st_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
              }

              if (!arg1) {
                tcg_gen_movi_i32(t1, 0);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx2));
              } else {
                tcg_gen_st_tl(arg1, cpu_env, offsetof(OurCPUState,tempidx2));
              }
            }

            tcg_temp_free_i32(t0);
            tcg_temp_free_i32(t1);
            tcg_temp_free_i32(t2);

          }
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 64
        } else /*if (nb_iargs == 4)*/ {
          tcg_abort();
        }
#endif
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      default:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;
    } /* End switch */
  } /* End taint while loop */

  global_taint_flag = 0;

  // if (check(gen_old_op_buf, gen_old_opparam_buf))
  //   qemu_log("BUFFERS ARE EQUAL!\n");
  // else
  //   qemu_log("NOPE\n");

  return return_lj;
#else
  return 0;
#endif /* CONFIG_TCG_TAINT */
}

#endif /* CONFIG_2nd_CCACHE */

int gen_taintcheck_insn()
{
  global_taint_flag = 1;

#ifdef CONFIG_TCG_TAINT
  /* Opcode and parameter buffers */
  static TCGOp gen_old_op_buf[OPC_BUF_SIZE];
  static TCGArg gen_old_opparam_buf[OPPARAM_BUF_SIZE];

  int num_op = tcg_ctx.gen_next_op_idx;
  int num_parm = tcg_ctx.gen_next_parm_idx;
  int return_lj = -1;

  int nb_args=0;
  op_index=0;
  int i=0;
  TCGOpcode opc=0;
  int nb_oargs=0, nb_iargs=0, nb_cargs=0;
  TCGv arg0, arg1, arg2, arg3, arg4, arg5;
  TCGv t0, t1, t2, t3, t4, t_zero;
#if defined(TARGET_I386)
  TCGv arg6, t5, t6;
#endif /* TARGET check */
  TCGv orig0, orig1, orig2, orig3, orig4, orig5;

  gen_op_ptr = tcg_ctx.gen_op_buf;
  gen_opparam_ptr = tcg_ctx.gen_opparam_buf;

  /* Copy and instrument the opcodes that need taint tracking */
  while(op_index < num_op) {
    /* Copy the op and the appropriate number of arguments for the opcode */
    gen_op_ptr++;
    op_index++;

    /* Copy the opcode to be instrumented */
    opc = gen_op_ptr[-1].opc;

    /* Determine the number and type of arguments for the opcode */
    if (opc == INDEX_op_call) {
      nb_oargs = gen_op_ptr[-1].callo;
      nb_iargs = gen_op_ptr[-1].calli;
      nb_cargs = tcg_op_defs[opc].nb_cargs;
      nb_args = nb_oargs + nb_iargs + 2; // N out args + N in args + (1) func + (1) flags (take a look at tcg_gen_callN())
    } else {
      nb_args = tcg_op_defs[opc].nb_args;
      nb_oargs = tcg_op_defs[opc].nb_oargs;
      nb_iargs = tcg_op_defs[opc].nb_iargs;
      nb_cargs = tcg_op_defs[opc].nb_cargs;
    }

    gen_opparam_ptr = tcg_ctx.gen_opparam_buf + gen_op_ptr[-1].args + nb_args;

    switch(opc)
    {
      /* The following opcodes propagate no taint */
      case INDEX_op_set_label:
      case INDEX_op_insn_start:
      case INDEX_op_goto_tb:
      case INDEX_op_exit_tb:
      case INDEX_op_br:
      case INDEX_op_brcond_i32:
#if (TCG_TARGET_REG_BITS == 32)
      case INDEX_op_brcond2_i32:
#endif /* TCG_TARGET_REG_BITS */
      case INDEX_op_brcond_i64:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_discard:      // Remove associated shadow reg
        arg0 = find_shadow_arg(gen_old_opparam_buf[-1]);
        if (arg0) {
          /* Insert taint IR */
          tcg_gen_discard_tl(arg0);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_call:         // Always bit taint
        // Call is a bit different, because it has a constant arg
        // that comes before the input args (if any).  That constant
        // says how many arguments follow, since the Call op has a
        // variable number of arguments
        // [OP][# of args breakdown(const)][arg0(I/O][arg1(I/O)]...
        //    [argN(I)][# of args (const)]

        if (!strcmp("swl", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs])) || !strcmp("swr", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs]))) {
          call_taint = 1;
          goto qemu_st_i32;
        }

        if (!strcmp("skip_taint_right_shift_amount_enter", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs]))) {
          skip_taint_right_shift_amount = 1;
        }

        if (!strcmp("skip_taint_right_shift_amount_exit", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs]))) {
          skip_taint_right_shift_amount = 0;
        }

        if (!strcmp("skip_taint_left_shift_amount_enter", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs]))) {
          skip_taint_left_shift_amount = 1;
        }

        if (!strcmp("skip_taint_left_shift_amount_exit", tcg_find_helper(&tcg_ctx, tcg_ctx.gen_opparam_buf[gen_op_ptr[-1].args + nb_oargs + nb_iargs]))) {
          skip_taint_left_shift_amount = 0;
        }

        for (i=0; i < nb_oargs; i++) {
          arg0 = find_shadow_arg(gen_opparam_ptr[
            (-1 * nb_args) /* Position of first argument in opcode stream */
            + i	/* Skip to the output parm that we are interested in */
          ]);
          if (arg0) {
          /* Insert taint IR */
            tcg_gen_movi_i32(arg0, 0);
          }
        }
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_deposit_i32:  // Always bitwise taint
        arg0 = find_shadow_arg(gen_opparam_ptr[-5]); // Output
        if (arg0) {
          int pos, len; // Constant parameters

          arg1 = find_shadow_arg(gen_opparam_ptr[-4]); // Input1
          arg2 = find_shadow_arg(gen_opparam_ptr[-3]); // Input2

          pos = gen_opparam_ptr[-2]; // Position of mask
          len = gen_opparam_ptr[-1]; // Length of mask

          /* Insert taint IR */
          // Handle special 32-bit transfer case (copy arg2 taint)
          if (len == 32) {
            tcg_gen_mov_i32(arg0, arg2);
          }
          // Handle special 0-bit transfer case (copy arg1 taint)
          else if (len == 0) {
            tcg_gen_mov_i32(arg0, arg1);
          }
          // Handle general case
          else {
            tcg_gen_deposit_tl(arg0, arg1, arg2, pos, len);
          }
        }
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

#if TCG_TARGET_REG_BITS == 32
      case INDEX_op_setcond2_i32: // All-Around: UifU64() w/ mkPCastTo()
        arg0 = find_shadow_arg(gen_opparam_ptr[-6]); // Output
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-5]); // Input1 low
          arg2 = find_shadow_arg(gen_opparam_ptr[-4]); // Input1 high
          arg3 = find_shadow_arg(gen_opparam_ptr[-3]); // Input2 low
          arg4 = find_shadow_arg(gen_opparam_ptr[-2]); // Input2 high

          /* Insert taint IR */
          // Combine high/low taint of Input 1 into t2
          t2 = tcg_temp_new_i32();
          if (arg1 && arg2) {
            tcg_gen_or_i32(t2, arg1, arg2);
          }
          else if (arg1) {
            tcg_gen_mov_i32(t2, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i32(t2, arg2);
          }
          else {
            tcg_gen_movi_i32(t2, 0);
          }

          // Combine high/low taint of Input 2 into t3
          t3 = tcg_temp_new_i32();
          if (arg3 && arg4) {
            tcg_gen_or_i32(t3, arg3, arg4);
          }
          else if (arg3) {
            tcg_gen_mov_i32(t3, arg3);
          }
          else if (arg4) {
            tcg_gen_mov_i32(t3, arg4);
          }
          else {
            tcg_gen_movi_i32(t3, 0);
          }

          // Determine if there is any taint
          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          tcg_gen_or_i32(t0, t2, t3);
          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t2, t0, t_zero); // Reuse t2
          tcg_gen_neg_i32(arg0, t2);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);
          tcg_temp_free_i32(t_zero);          
        }
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;
#endif /* TCG_TARGET_REG_BITS */

      case INDEX_op_movi_i32:     // Always bit taint
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          /* Insert taint IR */
          tcg_gen_movi_i32(arg0, 0);
        }
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_mov_i32:      // Always bit taint
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
        if (arg0) {
          /* Insert taint IR */
          if (arg1) {
            tcg_gen_mov_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
            tcg_gen_movi_i32(arg0, 0);
          }
          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
            gen_helper_debug_taint(arg1);
          }
        }
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      /* Load/store operations (32 bit). */
      /* MemCheck: mkLazyN() (Just load/store taint from/to memory) */
      case INDEX_op_qemu_ld_i32:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        // TARGET_REG_BITS = 64 OR (TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32)
        if (nb_iargs == 1) arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 64
        else tcg_abort(); // Not supported

        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);

          if (arg1) {
#if (TCG_TARGET_REG_BITS == 64)
            t0 = tcg_temp_new_i64();
            t1 = tcg_temp_new_i64();
            t2 = tcg_temp_new_i64();
            t3 = tcg_temp_new_i64();

#if defined(TARGET_MIPS)
            /* Load taint from tempidx */
            tcg_gen_ld32u_tl(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

#ifndef TAINT_NEW_POINTER //more selective pointer tainting
            t_zero = tcg_temp_new_i64();
            tcg_gen_movi_i64(t_zero, 0);

            tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t_zero);
            tcg_temp_free_i64(t_zero);
#else
            t4 = tcg_temp_new_i64();
            tcg_gen_movi_i64(t2, 0xffff0000);
            tcg_gen_and_i64(t0, arg1, t2);//t0 = H_taint
            tcg_gen_movi_i64(t2, 0);
            tcg_gen_setcond_i64(TCG_COND_EQ, t1, t0, t2);  //t1=(H_taint==0) cond1

            tcg_gen_setcond_i64(TCG_COND_NE, t4, arg1, t2);  //t4=(P_taint!=0) cond2
            tcg_gen_and_i64(t2, t1, t4); //t2 = cond1 & cond2
            tcg_temp_free_i64(t4);
#endif
            tcg_gen_neg_i64(t0, t2);

            /* Combine pointer and tempidx taint */
            // tcg_gen_or_i64(arg0, t0, t3);  // Overtaint
            tcg_gen_mov_i64(arg0, t3);

            tcg_temp_free_i64(t0);
            tcg_temp_free_i64(t1);
            tcg_temp_free_i64(t2);
            tcg_temp_free_i64(t3);
#else
            t0 = tcg_temp_new_i32();
            t1 = tcg_temp_new_i32();
            t2 = tcg_temp_new_i32();
            t3 = tcg_temp_new_i32();

#if defined(TARGET_MIPS)
            /* Load taint from tempidx */
            tcg_gen_ld_i32(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

#ifndef TAINT_NEW_POINTER
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);

            tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t_zero);
            tcg_temp_free_i32(t_zero);
#else
            t4 = tcg_temp_new_i32();
            tcg_gen_movi_i32(t2, 0xffff0000); //??
            tcg_gen_and_i32(t0, arg1, t2);//t0 = H_taint
            tcg_gen_movi_i32(t2, 0);
            tcg_gen_setcond_i32(TCG_COND_EQ, t1, t0, t2);  //t1=(H_taint==0) cond1

            tcg_gen_setcond_i32(TCG_COND_NE, t4, arg1, t2);  //t4=(P_taint!=0) cond2
            tcg_gen_and_i32(t2, t1, t4); //t2 = cond1 & cond2
            tcg_temp_free_i32(t4);
#endif
            tcg_gen_neg_i32(t0, t2);
            /* Combine pointer and tempidx taint */
            // tcg_gen_or_i32(arg0, t0, t3);  // Overtaint
            tcg_gen_mov_i32(arg0, t3);

            tcg_temp_free_i32(t0);
            tcg_temp_free_i32(t1);
            tcg_temp_free_i32(t2);
            tcg_temp_free_i32(t3);
#endif /* TARGET_REG_BITS */

          } else {
#if defined(TARGET_MIPS)
            /* Patch in opcode to load taint from tempidx */
            tcg_gen_ld_i32(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
          }
        }
        break;

      case INDEX_op_qemu_ld_i64:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

#ifdef DUMMY_TAINT_FOR_64BIT // AWH - FIXME: 64-bit memory ops may cause corruption
        DUMMY_TAINT(nb_oargs, nb_args);
#else
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32
        if ((nb_oargs == 2) && (nb_iargs == 1)) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Taint of low DWORD
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Taint of hi DWORD
          if (arg0 || arg1) {
            arg2 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg2) {
              t0 = tcg_temp_new_i32();
              t1 = tcg_temp_new_i32();
              t2 = tcg_temp_new_i32();
              t3 = tcg_temp_new_i32();

#if defined(TARGET_MIPS)
              /* Load taint from tempidx */
              tcg_gen_ld_i32(t2, cpu_env, offsetof(OurCPUState,tempidx));
              tcg_gen_ld_i32(t3, cpu_env, offsetof(OurCPUState, tempidx2));
#endif

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i32();
              tcg_gen_movi_i32(t_zero, 0);

              tcg_gen_setcond_i32(TCG_COND_NE, t1, arg2, t_zero);
              tcg_gen_neg_i32(t0, t1);

              /* Combine pointer and tempidx taint */
              if (arg0) {
                // tcg_gen_or_i32(arg0, t0, t2);  // Overtaint
                tcg_gen_mov_i32(arg0, t2);
              }
              if (arg1) {
                // tcg_gen_or_i32(arg1, t0, t3);  // Overtaint
                tcg_gen_mov_i32(arg1, t3);
              }

              tcg_temp_free_i32(t_zero);
              tcg_temp_free_i32(t0);
              tcg_temp_free_i32(t1);
              tcg_temp_free_i32(t2);
              tcg_temp_free_i32(t3);                

            } else {
#if defined(TARGET_MIPS)
              /* Patch in opcode to load taint from tempidx */
              if (arg0) {
                tcg_gen_ld_i32(arg0, cpu_env, offsetof(OurCPUState,tempidx));
              }
              if (arg1) {
                tcg_gen_ld_i32(arg1, cpu_env, offsetof(OurCPUState,tempidx2));
              }
#endif
            }
          }
        // TARGET_REG_BITS = 64, TARGET_LONG_BITS = 64
        } else if ((nb_oargs ==1) && (nb_iargs == 1)) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
          if (arg0) {
            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg1) {
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();
              t3 = tcg_temp_new_i64();

#if defined(TARGET_MIPS)
              /* Load taint from tempidx */
              tcg_gen_ld_i64(t3, cpu_env, offsetof(OurCPUState,tempidx));
#endif

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i64();
              tcg_gen_movi_i64(t_zero, 0);

              tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t_zero);
              tcg_gen_neg_i64(t0, t2);

              /* Combine pointer and tempidx taint */
              // tcg_gen_or_i64(arg0, t0, t3);  // Overtaint
              tcg_gen_mov_i64(arg0, t3);

              tcg_temp_free_i64(t_zero);
              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
              tcg_temp_free_i64(t3);
            } else {
#if defined(TARGET_MIPS)
              /* Patch in opcode to load taint from tempidx */
              tcg_gen_ld_i64(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
            }
          }
        // TARGET_REG_BITS = 64, TARGET_LONG_BITS = 32
        } else
          tcg_abort();
#endif // FIXME
        break;

      case INDEX_op_qemu_st_i32:
qemu_st_i32:
        // TARGET_REG_BITS = 64 OR (TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32)
        if (nb_iargs == 2 || call_taint) {
          arg0 = call_taint ? find_shadow_arg(gen_opparam_ptr[-5]) : find_shadow_arg(gen_opparam_ptr[-3]);
          
          if (!call_taint)
            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);

          if (arg0) {
            /* Save the qemu_st* parameters */
            int mem_index = gen_opparam_ptr[-1];
            int addr = gen_opparam_ptr[-2];
            int ret = gen_opparam_ptr[-3];
            int ir = gen_op_ptr[-1].opc;

            if (arg1) {

#if (TCG_TARGET_REG_BITS == 64)
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i64();
              tcg_gen_movi_i64(t_zero, 0);
              tcg_gen_movi_i64(t0, 0);
              tcg_gen_movi_i64(t2, 0);

              if (!call_taint) {
                tcg_gen_setcond_i64(TCG_COND_NE, t2, arg0, t_zero);
                tcg_gen_neg_i64(t0, t2);
              }

              /* Combine pointer and data taint */
              // tcg_gen_or_i64(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i64(t1, arg0);
#if defined(TARGET_MIPS)
              /* Store combined taint to tempidx */
              tcg_gen_st32_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
#endif

              tcg_temp_free_i64(t_zero);
              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
#else
              t0 = tcg_temp_new_i32();
              t1 = tcg_temp_new_i32();
              t2 = tcg_temp_new_i32();

              /* Check for pointer taint */
              t_zero = tcg_temp_new_i32();
              tcg_gen_movi_i32(t_zero, 0);
              tcg_gen_movi_i32(t0, 0);
              tcg_gen_movi_i32(t2, 0);

              if (!call_taint) {
                tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t_zero);
                tcg_gen_neg_i32(t0, t2);
              }

              /* Combine pointer and data taint */
              // tcg_gen_or_i32(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i32(t1, arg0);
#if defined(TARGET_MIPS)
              /* Store combined taint to tempidx */
              tcg_gen_st32_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
#endif
              tcg_temp_free_i32(t_zero);
              tcg_temp_free_i32(t0);
              tcg_temp_free_i32(t1);
              tcg_temp_free_i32(t2);
#endif /* TARGET_REG_BITS */

            } else {
#if defined(TARGET_MIPS)
              tcg_gen_st32_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
#endif
            }
          }
        } else
          tcg_abort();

        call_taint = 0;
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      case INDEX_op_qemu_st_i64:
#if defined(TARGET_MIPS)
        /* TARGET_REG_BITS == 64 */
        if (nb_iargs == 2) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
          if (arg0) {
            /* Save the qemu_st64 parameters */
            int mem_index = gen_opparam_ptr[-1];
            int addr = gen_opparam_ptr[-2];
            int ret = gen_opparam_ptr[-3];

            arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg1) {
              t0 = tcg_temp_new_i64();
              t1 = tcg_temp_new_i64();
              t2 = tcg_temp_new_i64();

              /* Check for pointer taint */
              tcg_gen_movi_i64(t1, 0);

              tcg_gen_setcond_i64(TCG_COND_NE, t2, arg1, t1);
              tcg_gen_neg_i64(t0, t2);

              /* Combine pointer and data taint */
              // tcg_gen_or_i64(t1, t0, arg0);  // Overtaint
              tcg_gen_mov_i64(t1, arg0);
              /* Store combined taint to tempidx */
              tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));

              tcg_temp_free_i64(t0);
              tcg_temp_free_i64(t1);
              tcg_temp_free_i64(t2);
            } else {
              tcg_gen_st_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
            }

          }
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 32
        } else if (nb_iargs == 3) {
          arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Taint of low DWORD
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Taint of high DWORD
          if (arg0 || arg1) {
            int ret_lo = gen_opparam_ptr[-4]; // Low DWORD of data
            int ret_hi = gen_opparam_ptr[-3]; // High DWORD of Data
            int addr = gen_opparam_ptr[-2]; // Addr
            int mem_index = gen_opparam_ptr[-1]; // MMU index

            t0 = tcg_temp_new_i32();
            t1 = tcg_temp_new_i32();
            t2 = tcg_temp_new_i32();
            arg2 = find_shadow_arg(gen_opparam_ptr[-2]);
            if (arg2) {
              /* Check for pointer taint */
              tcg_gen_movi_i32(t1, 0);

              tcg_gen_setcond_i32(TCG_COND_NE, t2, arg1, t1);
              tcg_gen_neg_i32(t0, t2);
              /* Combine pointer and data taint */
              if (!arg0) {
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx));
              }
              else {
                // tcg_gen_or_i32(t1, t0, arg0);  // Overtaint
                tcg_gen_mov_i32(t1, arg0);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx));
              }

              if (!arg1) {
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx2));
              }
              else {
                // tcg_gen_or_i32(t1, t0, arg1);  // Overtaint
                tcg_gen_mov_i32(t1, arg1);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx2));
              }

            } else {
              /* If there is no shadow data for either one of the 32-bit chunks
              that make up this 64-bit store, then use a zeroed-out temp reg
              to indicate there is no taint for that 32-bit chunk. */
              if (!arg0) {
                tcg_gen_movi_i32(t0, 0);
                tcg_gen_st_tl(t0, cpu_env, offsetof(OurCPUState,tempidx));
              } else {
                tcg_gen_st_tl(arg0, cpu_env, offsetof(OurCPUState,tempidx));
              }

              if (!arg1) {
                tcg_gen_movi_i32(t1, 0);
                tcg_gen_st_tl(t1, cpu_env, offsetof(OurCPUState,tempidx2));
              } else {
                tcg_gen_st_tl(arg1, cpu_env, offsetof(OurCPUState,tempidx2));
              }
            }

            tcg_temp_free_i32(t0);
            tcg_temp_free_i32(t1);
            tcg_temp_free_i32(t2);

          }
        // TARGET_REG_BITS = 32, TARGET_LONG_BITS = 64
        } else /*if (nb_iargs == 4)*/ {
          tcg_abort();
        }
#endif
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break;

      /* Arithmethic/shift/rotate operations (32 bit). */
      case INDEX_op_setcond_i32: // All-Around: UifU32() (mkLazy())
        arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Output
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Input1
          arg2 = find_shadow_arg(gen_opparam_ptr[-2]); // Input2

          if (arg1 && arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_or_i32(t0, arg1, arg2);
          } else if (arg1) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg1);
          } else if (arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg2);
          } else {
            tcg_gen_mov_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          // Determine if there is any taint
          t1 = tcg_temp_new_i32();
          t_zero = tcg_temp_new_i32();
          
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t1, t0, t_zero);
          tcg_gen_neg_i32(arg0, t1);

          char buf[128];
          tcg_get_arg_str_idx(&tcg_ctx, buf, sizeof(buf), gen_opparam_ptr[-4]);

          // if (!strcmp(buf, "bcond")) {
          //   gen_helper_trace_setcond_i32(cpu_env, arg0);
          // }

          tcg_temp_free_i32(t_zero);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t0);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      /* IN MEMCHECK (VALGRIND), LOOK AT: memcheck/mc_translate.c
         expr2vbits_Binop(), expr2vbits_Unop() */
      case INDEX_op_shl_i32: // Special - scalarShift()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg1);
            gen_helper_debug_taint(arg2);
          }

          /* Insert taint IR */
          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          if (arg2 && !skip_taint_left_shift_amount) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t1, t_zero, arg2);
            tcg_gen_neg_i32(t2, t1);
            tcg_temp_free_i32(t_zero);
          } else {
            tcg_gen_movi_i32(t2, 0);
          }

          if (arg1) {
            // Perform the SHL on arg1
            tcg_gen_shl_i32(t0, arg1, orig2);//tcg_gen_shl_i32(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i32(arg0, t0, t2);
          } else {
            tcg_gen_mov_i32(arg0, t2);
          }

          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t0);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        
        break;

      case INDEX_op_shr_i32: // Special - scalarShift()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg1);
            gen_helper_debug_taint(arg2);
          }

          /* Insert taint IR */
          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          if (arg2 && !skip_taint_right_shift_amount) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t1, t_zero, arg2);
            tcg_gen_neg_i32(t2, t1);
            tcg_temp_free_i32(t_zero);
          } else {
            tcg_gen_movi_i32(t2, 0);
          }

          if (arg1) {
            // Perform the SHR on arg1
            tcg_gen_shr_i32(t0, arg1, orig2);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i32(arg0, t0, t2);
          } else {
            tcg_gen_mov_i32(arg0, t2);
          }

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_sar_i32: // Special - scalarShift()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          /* Insert taint IR */
          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t1, t_zero, arg2);
            tcg_gen_neg_i32(t2, t1);
            tcg_temp_free_i32(t_zero);
          } else {
            tcg_gen_movi_i32(t2, 0);
          }

          if (arg1) {
            // Perform the SAR on arg1
            tcg_gen_sar_i32(t0, arg1, orig2);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i32(arg0, t0, t2);
          } else {
            tcg_gen_mov_i32(arg0, t2);
          }

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);        
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_rot_i32
      case INDEX_op_rotl_i32: // Special - MemCheck does lazy, but we shift
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);


          /* Insert tainting IR */
          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t1, t_zero, arg2);
            tcg_gen_neg_i32(t2, t1);

            tcg_temp_free_i32(t_zero);
          } else {
            tcg_gen_movi_i32(t2, 0);
          }

          if (arg1) {
            // Perform the ROTL on arg1
            tcg_gen_rotl_i32(t0, arg1, orig2);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i32(arg0, t0, t2);
          } else {
            tcg_gen_mov_i32(arg0, t2);
          }

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_rotr_i32: // Special - MemCheck does lazy, but we shift
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          /* Insert tainting IR */
          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t1, t_zero, arg2);
            tcg_gen_neg_i32(t2, t1);
            tcg_temp_free_i32(t_zero);
          } else {
            tcg_gen_movi_i32(t2, 0);
          }

          if (arg1) {
            // Perform the ROTR on arg1
            tcg_gen_rotr_i32(t0, arg1, orig2);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i32(arg0, t0, t2);
          } else {
            tcg_gen_mov_i32(arg0, t2);
          }

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
        }
        
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#endif /* TCG_TARGET_HAS_rot_i32 */
#ifdef TCG_BITWISE_TAINT
#ifdef TAINT_EXPENSIVE_ADDSUB
 // AWH - expensiveAddSub() for add_i32/or_i32 are buggy, use cheap one
      /* T0 = (T1 | T2) | ((V1_min + V2_min) ^ (V1_max + V2_max)) */
      case INDEX_op_add_i32: // Special - expensiveAddSub()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          //LOK: Changed the names of orig0 and orig 1 to orig1 and 2
          // so I don't get confused
          // Basically arg is vxx and orig is x
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          //LOK: Declared the new temporary variables that we need
          t0 = tcg_temp_new_i32(); //scratch
          t1 = tcg_temp_new_i32(); //a_min
          t2 = tcg_temp_new_i32(); //b_min
          t3 = tcg_temp_new_i32(); //a_max
          t4 = tcg_temp_new_i32(); //b_max

          /* Per the expensiveAddSub() logic:
             qaa = T1 = arg1
             qbb = T2 = arg2
             aa  = V1 = orig1
             bb  = V2 = orig2 */

          //LOK: First lets calculate a_min = aa & ~qaa
          tcg_gen_not_i32(t0, arg1); // ~qaa
          tcg_gen_and_i32(t1, orig1, t0);//t1 = aa & ~qaa

          //LOK: Then calculate b_min
          tcg_gen_not_i32(t0, arg2); // ~qbb
          tcg_gen_and_i32(t2, orig2, t0);//t2 = bb & ~qbb

          //LOK: Then calculate a_max = aa | qaa
          tcg_gen_or_i32(t3, orig1, arg1);//t3 = aa | qaa
          tcg_gen_or_i32(t4, orig2, arg2);//t4 = bb | qbb

          //LOK: Now that we have the mins and maxes, we need to sum them
          tcg_gen_add_i32(t0, t3, t4); // t0 = a_max + b_max
          //LOK: Note that t3 is being reused in this case
          tcg_gen_add_i32(t3, t1, t2); // t3 = a_min + b_min
          tcg_gen_xor_i32(t1, t0, t3); // t1 = ((a_min + b_min)^(a_max + b_max))
          tcg_gen_or_i32(t0, arg1, arg2); // t0 = qa | qb
          tcg_gen_or_i32(arg0, t0, t1); // arg0 = (qa | qb) | ( (a_min + b_min) ^ (a_max + b_max)

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);
          tcg_temp_free_i32(t4);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
      /* T0 = (T1 | T2) | ((V1_min - V2_max) ^ (V1_max - V2_min)) */
      case INDEX_op_sub_i32: // Special - expensiveAddSub()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          //NOTE: It is important that we get the order of the operands correct
          // Right now, the assumption is
          // arg0 = arg1 - arg2
          // If there are errors - this could be the culprit

          //LOK: Changed the names of orig0 and orig 1 to orig1 and 2
          // so I don't get confused
          // Basically arg is vxx and orig is x
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);


          //LOK: Declared the new temporary variables that we need
          t0 = tcg_temp_new_i32(); //scratch
          t1 = tcg_temp_new_i32(); //a_min
          t2 = tcg_temp_new_i32(); //b_min
          t3 = tcg_temp_new_i32(); //a_max
          t4 = tcg_temp_new_i32(); //b_max

          /* Per the expensiveAddSub() logic:
             qaa = T1 = arg1
             qbb = T2 = arg2
             aa  = V1 = orig1
             bb  = V2 = orig2 */

          //LOK: First lets calculate a_min = aa & ~qaa
          tcg_gen_not_i32(t0, arg1); // ~qaa
          tcg_gen_and_i32(t1, orig1, t0);//t1 = aa & ~qaa

          //LOK: Then calculate b_min
          tcg_gen_not_i32(t0, arg2); // ~qbb
          tcg_gen_and_i32(t2, orig2, t0);//t2 = bb & ~qbb

          //LOK: Then calculate a_max = aa | qaa
          tcg_gen_or_i32(t3, orig1, arg1);//t3 = aa | qaa
          tcg_gen_or_i32(t4, orig2, arg2);//t4 = bb | qbb

          //LOK: Now that we have the mins and maxes, we need to find the differences
          //NOTE: This is why the order of the operands is important
          tcg_gen_sub_i32(t0, t1, t4); // t0 = a_min - b_max
          //LOK: Note that t3 is being reused in this case
          tcg_gen_sub_i32(t4, t3, t2); // t4 = a_max - b_min
          tcg_gen_xor_i32(t1, t0, t4); // t1 = ((a_min - b_max)^(a_max - b_min))
          tcg_gen_or_i32(t0, arg1, arg2); // t0 = qa | qb
          tcg_gen_or_i32(arg0, t0, t1); // arg0 = (qa | qb) | ( (a_min - b_max) ^ (a_max - b_min)

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);
          tcg_temp_free_i32(t4);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
 // AWH
#else
      case INDEX_op_add_i32: // Up - cheap_AddSub32
      case INDEX_op_sub_i32: // Up - cheap_AddSub32
#endif
      case INDEX_op_mul_i32: // Up - mkUifU32(), mkLeft32(), mkPCastTo()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          if (arg1 && arg2) {
            // mkUifU32(arg1, arg2)
            tcg_gen_or_i32(t0, arg1, arg2);
          }
          else if (arg1) {
            tcg_gen_movi_i32(t0, arg1);
          }
          else if (arg2) {
            tcg_gen_movi_i32(t0, arg2);
          }

          // mkLeft32(t0)
          t1 = tcg_temp_new_i32();
          tcg_gen_neg_i32(t1, t0); // (-s32)
          tcg_gen_or_i32(arg0, t0, t1); // (s32 | (-s32)) -> vLo32

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      /* Bitwise AND rules:
        Taint1 Value1 Op  Taint2 Value2  ResultingTaint
        0      1      AND 1      X       1
        1      X      AND 0      1       1
        1      X      AND 1      X       1
        ... otherwise, ResultingTaint = 0
        AND: ((NOT T1) * V1 * T2) + (T1 * (NOT T2) * V2) + (T1 * T2)
      */
      case INDEX_op_and_i32: // Special - and_or_ty()
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg1);
            gen_helper_debug_taint(arg2);
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t3 = tcg_temp_new_i32();

          /* T1 -> arg1
             V1 -> gen_opparam_ptr[-2]
             T2 -> arg2
             V2 -> gen_opparam_ptr[-1] */
          if (arg1) {
            tcg_gen_not_i32(t0, arg1); // NOT T1
          }
          else {
            tcg_gen_movi_i32(t0, -1);
          }
          if (arg2) {
            tcg_gen_and_i32(t1,orig1,arg2);//tcg_gen_and_i32(t1, gen_opparam_ptr[-2], arg2); // V1 * T2
          }
          else {
            tcg_gen_movi_i32(t1, 0);
          }
          tcg_gen_and_i32(t2, t0, t1); // (NOT T1) * V1 * T2

          if (arg2) {
            tcg_gen_not_i32(t0, arg2); // NOT T2
          }
          else {
            tcg_gen_movi_i32(t0, -1);
          }
          if (arg1) {
            tcg_gen_and_i32(t1,arg1,orig0);//tcg_gen_and_i32(t1, arg1, gen_opparam_ptr[-1]); // T1 * V2
          }
          else {
            tcg_gen_movi_i32(t1, 0);
          }
          tcg_gen_and_i32(t3, t0, t1); // (T1 * (NOT T2) * V2)

          if (arg1 && arg2) {
            tcg_gen_and_i32(t0, arg1, arg2); // T1 * T2
          }
          else {
            tcg_gen_movi_i32(t0, 0);
          }

          // OR it all together
          tcg_gen_or_i32(t1, t2, t3);
          tcg_gen_or_i32(arg0, t0, t1);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      /* Bitwise OR rules:
        Taint1 Value1 Op  Taint2 Value2  ResultingTaint
        0      0      OR  1      X       1
        1      X      OR  0      0       1
        1      X      OR  1      X       1
        ... otherwise, ResultingTaint = 0
        OR: ((NOT T1) * (NOT V1) * T2) + (T1 * (NOT T2) * (NOT V2)) + (T1 * T2)
      */
      case INDEX_op_or_i32: // Special - and_or_ty()
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg1);
            gen_helper_debug_taint(arg2);
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t3 = tcg_temp_new_i32();

          /* T1 -> arg1
             V1 -> gen_opparam_ptr[-2]
             T2 -> arg2
             V2 -> gen_opparam_ptr[-1] */
          if (arg1) {
            tcg_gen_not_i32(t0, arg1); // NOT T1
          }
          else {
            tcg_gen_movi_i32(t0, -1);
          }
          tcg_gen_not_i32(t1, orig1);//tcg_gen_not_i32(t1, gen_opparam_ptr[-2]); // NOT V1
          tcg_gen_and_i32(t2, t0, t1); // (NOT T1) * (NOT V1)
          if (arg2) {
            tcg_gen_and_i32(t0, t2, arg2); // (NOT T1) * (NOT V1) * T2
          }
          else {
            tcg_gen_movi_i32(t0, 0);
          }

          if (arg2) {
            tcg_gen_not_i32(t1, arg2); // NOT T2
          }
          else {
            tcg_gen_movi_i32(t1, -1);
          }
          tcg_gen_not_i32(t2, orig0);//tcg_gen_not_i32(t2, gen_opparam_ptr[-1]); // NOT V2
          tcg_gen_and_i32(t3, t1, t2); // (NOT T2) * (NOT V2)
          if (arg1) {
            tcg_gen_and_i32(t1, t3, arg1); // (NOT T2) * (NOT V2) * T1
          }
          else {
            tcg_gen_movi_i32(t1, 0);
          }

          if (arg1 && arg2) {
            tcg_gen_and_i32(t2, arg1, arg2); // T1 * T2
          }
          else if (arg1) {
            tcg_gen_mov_i32(t2, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i32(t2, arg2);
          }
          // OR it all together
          tcg_gen_or_i32(t3, t0, t1);
          tcg_gen_or_i32(arg0, t2, t3);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#else
      /* Bytewise taint for arithmethic/shift/rotate operations (32 bit). */
      /* These all use the following pattern of shadow registers: */
      /* arg0 = arg1 op arg2.  To bitwise taint this pattern in shadow */
      /* registers, we use the following steps:
         Step 1: temp0 = arg1 or arg2
         Step 2: temp1 = 0
         Step 3: temp2 = (temp0 != temp1)
         Step 4: arg0 = ~temp2
         MemCheck: mkLazy2() for all of these */
      case INDEX_op_add_i32:
      case INDEX_op_sub_i32:
      case INDEX_op_and_i32:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        if (skip_taint_left_shift_amount || skip_taint_right_shift_amount)
          break;
      case INDEX_op_mul_i32:
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          /* Determine which args are shadowed */
          if (arg1 && arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_or_i32(t0, arg1, arg2);
          } else if (arg1) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg1);
          } else if (arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg2);
          } else {
            tcg_gen_movi_i32(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t2, t_zero, t0);
          tcg_gen_neg_i32(arg0, t2);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t_zero);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
      case INDEX_op_or_i32:
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          /* Determine which args are shadowed */
          if (arg1 && arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_or_i32(t0, arg1, arg2);
          } else if (arg1) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg1);
          } else if (arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg2);
          } else {
            tcg_gen_movi_i32(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          if (skip_taint_left_shift_amount || skip_taint_right_shift_amount) {
            tcg_gen_mov_i32(arg0, t0);
          }
          else {
            t_zero = tcg_temp_new_i32();
            tcg_gen_movi_i32(t_zero, 0);
            tcg_gen_setcond_i32(TCG_COND_NE, t2, t_zero, t0);
            tcg_gen_neg_i32(arg0, t2);
            tcg_temp_free_i32(t_zero);
          }

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_BITWISE_TAINT */
      case INDEX_op_mulu2_i32: // Bytewise, mkLazyN()
        arg0 = find_shadow_arg(gen_opparam_ptr[-4]);
        arg1 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0 && arg1) {
          arg2 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg3 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg2 && arg3) {
            t0 = tcg_temp_new_i32();
            tcg_gen_or_i32(t0, arg2, arg3);
          } else if (arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg2);
          } else if (arg3) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg3);
          } else {
            tcg_gen_movi_i32(arg0, 0);
            tcg_gen_movi_i32(arg1, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break; //LOK: this is a bug - need to break it
          }
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t2, t0, t_zero);
          tcg_gen_neg_i32(arg0, t2);
          tcg_gen_neg_i32(arg1, t2);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t_zero);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_add2_i32: // Bytewise, mkLazyN()
      case INDEX_op_sub2_i32: // Bytewise, mkLazyN()
        arg0 = find_shadow_arg(gen_opparam_ptr[-6]); // Output low
        arg1 = find_shadow_arg(gen_opparam_ptr[-5]); // Output high
        if (arg0 && arg1) {
          arg2 = find_shadow_arg(gen_opparam_ptr[-4]); // Input1 low
          arg3 = find_shadow_arg(gen_opparam_ptr[-3]); // Input1 high
          arg4 = find_shadow_arg(gen_opparam_ptr[-2]); // Input2 low
          arg5 = find_shadow_arg(gen_opparam_ptr[-1]); // Input2 high

          if (!(arg2 || arg3 || arg4 || arg5)) {
            tcg_gen_movi_i32(arg0, 0);
            tcg_gen_movi_i32(arg1, 0);
            
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t3 = tcg_temp_new_i32();

          // Combine high/low taint of Input 1 into t2
          if (arg2 && arg3) {
            tcg_gen_or_i32(t2, arg2, arg3);
          }
          else if (arg2) {
            tcg_gen_mov_i32(t2, arg2);
          }
          else if (arg3) {
            tcg_gen_mov_i32(t2, arg3);
          }
          else {
            tcg_gen_movi_i32(t2, 0);
          }

          // Combine high/low taint of Input 2 into t3
          if (arg4 && arg5) {
            tcg_gen_or_i32(t3, arg4, arg5);
          }
          else if (arg4) {
            tcg_gen_mov_i32(t3, arg4);
          }
          else if (arg5) {
            tcg_gen_mov_i32(t3, arg5);
          }
          else {
            tcg_gen_movi_i32(t3, 0);
          }

          // Determine if there is any taint
          tcg_gen_or_i32(t0, t2, t3);
          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t2, t0, t_zero); // Reuse t2
          tcg_gen_neg_i32(arg0, t2);
          tcg_gen_neg_i32(arg1, t2);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t3);
          tcg_temp_free_i32(t_zero);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_xor_i32: // In-Place - mkUifU32
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg1);
            gen_helper_debug_taint(arg2);
          }

          /* Perform an OR an arg1 and arg2 to find taint */
          if (arg1 && arg2) {
            tcg_gen_or_i32(arg0, arg1, arg2);
          }
          else if (arg1) {
            tcg_gen_mov_i32(arg0, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i32(arg0, arg2);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }

          if (skip_taint_right_shift_amount && debug) {
            gen_helper_debug_taint(arg0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_div_i32
      case INDEX_op_div_i32: // All-around: mkLazy2()
      case INDEX_op_divu_i32: // All-around: mkLazy2()
      case INDEX_op_rem_i32: // All-around: mkLazy2()
      case INDEX_op_remu_i32: // All-around: mkLazy2()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1 && arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_or_i32(t0, arg1, arg2);
          } else if (arg1) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg1);
          } else if (arg2) {
            t0 = tcg_temp_new_i32();
            tcg_gen_mov_i32(t0, arg2);
          } else {
            tcg_gen_movi_i32(arg0, 0);
            break;
          }
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();
          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t2, t0, t_zero);
          tcg_gen_neg_i32(arg0, t2);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t_zero);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#elif TCG_TARGET_HAS_div2_i32
      case INDEX_op_div2_i32: // All-around: mkLazy3()
      case INDEX_op_divu2_i32: // All-around: mkLazy3()
        arg0 = find_shadow_arg(gen_opparam_ptr[-5]);
        arg1 = find_shadow_arg(gen_opparam_ptr[-4]);
        if (arg0 && arg1) {
          arg2 = find_shadow_arg(gen_opparam_ptr[-3]);
          arg3 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg4 = find_shadow_arg(gen_opparam_ptr[-1]);

          /* No shadows for any inputs */
          if (!(arg2 || arg3 || arg4))
          {
            tcg_gen_movi_i32(arg0, 0);
            tcg_gen_movi_i32(arg1, 0);
            
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t0 = tcg_temp_new_i32();
          t1 = tcg_temp_new_i32();
          t2 = tcg_temp_new_i32();

          /* Check for shadows on arg2 and arg3 */
          if (arg2 && arg3) {
            tcg_gen_or_i32(t0, arg2, arg3);
          }
          else if (arg2) {
            tcg_gen_mov_i32(t0, arg2);
          }
          else if (arg3) {
            tcg_gen_mov_i32(t0, arg3);
          }
          else {
            tcg_gen_movi_i32(t0, 0);
          }

          /* Check for shadow on arg4 */
          if (arg4) {
            tcg_gen_or_i32(t2, t0, arg4);
          }
          else {
            tcg_gen_mov_i32(t2, t0);
          }

          t_zero = tcg_temp_new_i32();
          tcg_gen_movi_i32(t_zero, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t0, t2, t_zero);
          tcg_gen_neg_i32(arg0, t0);
          tcg_gen_neg_i32(arg1, t0);

          tcg_temp_free_i32(t0);
          tcg_temp_free_i32(t1);
          tcg_temp_free_i32(t2);
          tcg_temp_free_i32(t_zero);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_div*_i32 */

#if TCG_TARGET_HAS_ext8s_i32
      case INDEX_op_ext8s_i32: // MemCheck: VgT_SWiden14
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext8s_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        
        break;
#endif /* TCG_TARGET_HAS_ext8s_i32 */
#if TCG_TARGET_HAS_ext16s_i32
      case INDEX_op_ext16s_i32: // MemCheck: VgT_SWiden24
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext16s_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext16s_i32 */
#if TCG_TARGET_HAS_ext8u_i32
      case INDEX_op_ext8u_i32: // MemCheck: VgT_ZWiden14
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1) {
            tcg_gen_ext8u_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext8u_i32 */
#if TCG_TARGET_HAS_ext16u_i32
      case INDEX_op_ext16u_i32: // MemCheck: VgT_ZWiden24
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1) {
            tcg_gen_ext16u_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext16u_i32 */
#if TCG_TARGET_HAS_bswap16_i32
      case INDEX_op_bswap16_i32: // MemCheck: UifU2
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_bswap16_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_bswap16_i32 */
#if TCG_TARGET_HAS_bswap32_i32
      case INDEX_op_bswap32_i32: // MemCheck: UifU4
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1) {
            tcg_gen_bswap32_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_bswap32_i32 */
#if TCG_TARGET_HAS_not_i32
      case INDEX_op_not_i32: // MemCheck: Nothing! (Returns orig atom)
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1) {
            tcg_gen_mov_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_not_i32 */
#if TCG_TARGET_HAS_neg_i32
      case INDEX_op_neg_i32:
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1) {
            tcg_gen_mov_i32(arg0, arg1);
          }
          else {
            tcg_gen_movi_i32(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#endif /* TCG_TARGET_HAS_neg_i32 */

      case INDEX_op_movi_i64:
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          tcg_gen_movi_i64(arg0, 0);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_mov_i64:
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
        if (arg0) {
          if (arg1) {
            tcg_gen_mov_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      /* Arithmethic/shift/rotate operations (64 bit). */
      case INDEX_op_setcond_i64: // All-Around: UifU64() (mkLazy())
        arg0 = find_shadow_arg(gen_opparam_ptr[-4]); // Output
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-3]); // Input1
          arg2 = find_shadow_arg(gen_opparam_ptr[-2]); // Input2

          if (arg1 && arg2) {
            t0 = tcg_temp_new_i64();
            tcg_gen_or_i64(t0, arg1, arg2);
          } else if (arg1) {
            t0 = tcg_temp_new_i64();
            tcg_gen_mov_i64(t0, arg1);
          } else if (arg2) {
            t0 = tcg_temp_new_i64();
            tcg_gen_mov_i64(t0, arg2);
          } else {
            tcg_gen_mov_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          // Determine if there is any taint
          t1 = tcg_temp_new_i64();
          t_zero = tcg_temp_new_i64();

          tcg_gen_movi_i64(t_zero, 0);
          tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, t_zero);
          tcg_gen_neg_i64(arg0, t1);

          char buf[128];
          tcg_get_arg_str_idx(&tcg_ctx, buf, sizeof(buf), gen_opparam_ptr[-4]);

          // if (!strcmp(buf, "bcond")) {
          //   gen_helper_trace_setcond_i64(cpu_env, arg0);
          // }

          tcg_temp_free_i64(t_zero);
          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#ifdef TCG_BITWISE_TAINT
      case INDEX_op_shl_i64: // Special - scalarShift()
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            tcg_gen_movi_i64(t0, 0);
            tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, arg2);
            tcg_gen_neg_i64(t2, t1);
          } else {
            tcg_gen_movi_i64(t2, 0);
          }

          if (arg1) {
            // Perform the SHL on arg1
        	  tcg_gen_shl_i64(t0, arg1, orig0); // tcg_gen_shl_i64(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i64(arg0, t0, t2);
          } else {
            tcg_gen_mov_i64(arg0, t2);
          }

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_shr_i64: // Special - scalarShift()
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            tcg_gen_movi_i64(t0, 0);
            tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, arg2);
            tcg_gen_neg_i64(t2, t1);
          } else {
            tcg_gen_movi_i64(t2, 0);
          }

          if (arg1) {
            // Perform the SHR on arg1
        	  tcg_gen_shr_i64(t0, arg1, orig0); //tcg_gen_shr_i64(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i64(arg0, t0, t2);
          } else {
            tcg_gen_mov_i64(arg0, t2);
          }

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_sar_i64: // Special - scalarShift()
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            tcg_gen_movi_i64(t0, 0);
            tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, arg2);
            tcg_gen_neg_i64(t2, t1);
          } else {
            tcg_gen_movi_i64(t2, 0);
          }

          if (arg1) {
            // Perform the SAR on arg1
            tcg_gen_sar_i64(t0, arg1, orig0);//tcg_gen_sar_i64(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i64(arg0, t0, t2);
          } else {
            tcg_gen_mov_i64(arg0, t2);
          }

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_rot_i64
      case INDEX_op_rotl_i64: // Special - MemCheck does lazy, but we shift
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            tcg_gen_movi_i64(t0, 0);
            tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, arg2);
            tcg_gen_neg_i64(t2, t1);
          } else {
            tcg_gen_movi_i64(t2, 0);
          }

          if (arg1) {
            // Perform the ROTL on arg1
        	  tcg_gen_rotl_i64(t0, arg1, orig0); // tcg_gen_rotl_i64(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i64(arg0, t0, t2);
          } else {
            tcg_gen_mov_i64(arg0, t2);
          }

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_rotr_i64: // Special - MemCheck does lazy, but we shift
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (arg2) {
            // Check if the shift amount (arg2) is tainted.  If so, the
            // entire result will be tainted.
            tcg_gen_movi_i64(t0, 0);
            tcg_gen_setcond_i64(TCG_COND_NE, t1, t0, arg2);
            tcg_gen_neg_i64(t2, t1);
          } else {
            tcg_gen_movi_i64(t2, 0);
          }

          if (arg1) {
            // Perform the ROTL on arg1
        	  tcg_gen_rotr_i64(t0, arg1, orig0);//tcg_gen_rotr_i64(t0, arg1, gen_opparam_ptr[-1]);
            // OR together the taint of shifted arg1 (t0) and arg2 (t2)
            tcg_gen_or_i64(arg0, t0, t2);
          } else {
            tcg_gen_mov_i64(arg0, t2);
          }

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_rot_i64 */
 // AWH - expensiveAddSub() for add_i64/or_i64 are buggy, use cheap one
      /* T0 = (T1 | T2) | ((V1_min + V2_min) ^ (V1_max + V2_max)) */
      case INDEX_op_add_i64: // Special - expensiveAddSub()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          //LOK: Changed the names of orig0 and orig 1 to orig1 and 2
          // so I don't get confused
          // Basically arg is vxx and orig is x
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          //LOK: Declared the new temporary variables that we need
          t0 = tcg_temp_new_i64(); //scratch
          t1 = tcg_temp_new_i64(); //a_min
          t2 = tcg_temp_new_i64(); //b_min
          t3 = tcg_temp_new_i64(); //a_max
          t4 = tcg_temp_new_i64(); //b_max

          /* Per the expensiveAddSub() logic:
             qaa = T1 = arg1
             qbb = T2 = arg2
             aa  = V1 = orig1
             bb  = V2 = orig2 */

          //LOK: First lets calculate a_min = aa & ~qaa
          tcg_gen_not_i64(t0, arg1); // ~qaa
          tcg_gen_and_i64(t1, orig1, t0);//t1 = aa & ~qaa

          //LOK: Then calculate b_min
          tcg_gen_not_i64(t0, arg2); // ~qbb
          tcg_gen_and_i64(t2, orig2, t0);//t2 = bb & ~qbb

          //LOK: Then calculate a_max = aa | qaa
          tcg_gen_or_i64(t3, orig1, arg1);//t3 = aa | qaa
          tcg_gen_or_i64(t4, orig2, arg2);//t4 = bb | qbb

          //LOK: Now that we have the mins and maxes, we need to sum them
          tcg_gen_add_i64(t0, t3, t4); // t0 = a_max + b_max
          //LOK: Note that t3 is being reused in this case
          tcg_gen_add_i64(t3, t1, t2); // t3 = a_min + b_min
          tcg_gen_xor_i64(t1, t0, t3); // t1 = ((a_min + b_min)^(a_max + b_max))
          tcg_gen_or_i64(t0, arg1, arg2); // t0 = qa | qb
          tcg_gen_or_i64(arg0, t0, t1); // arg0 = (qa | qb) | ( (a_min + b_min) ^ (a_max + b_max)

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
          tcg_temp_free_i64(t3);
          tcg_temp_free_i64(t4);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      /* T0 = (T1 | T2) | ((V1_min - V2_max) ^ (V1_max - V2_min)) */
      case INDEX_op_sub_i64: // Special - expensiveAddSub()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          //NOTE: It is important that we get the order of the operands correct
          // Right now, the assumption is
          // arg0 = arg1 - arg2
          // If there are errors - this could be the culprit

          //LOK: Changed the names of orig0 and orig 1 to orig1 and 2
          // so I don't get confused
          // Basically arg is vxx and orig is x
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          orig2 = gen_opparam_ptr[-1];
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          //LOK: Declared the new temporary variables that we need
          t0 = tcg_temp_new_i64(); //scratch
          t1 = tcg_temp_new_i64(); //a_min
          t2 = tcg_temp_new_i64(); //b_min
          t3 = tcg_temp_new_i64(); //a_max
          t4 = tcg_temp_new_i64(); //b_max

          /* Per the expensiveAddSub() logic:
             qaa = T1 = arg1
             qbb = T2 = arg2
             aa  = V1 = orig1
             bb  = V2 = orig2 */

          //LOK: First lets calculate a_min = aa & ~qaa
          tcg_gen_not_i64(t0, arg1); // ~qaa
          tcg_gen_and_i64(t1, orig1, t0);//t1 = aa & ~qaa

          //LOK: Then calculate b_min
          tcg_gen_not_i64(t0, arg2); // ~qbb
          tcg_gen_and_i64(t2, orig2, t0);//t2 = bb & ~qbb

          //LOK: Then calculate a_max = aa | qaa
          tcg_gen_or_i64(t3, orig1, arg1);//t3 = aa | qaa
          tcg_gen_or_i64(t4, orig2, arg2);//t4 = bb | qbb

          //LOK: Now that we have the mins and maxes, we need to find the differences
          //NOTE: This is why the order of the operands is important
          tcg_gen_sub_i64(t0, t1, t4); // t0 = a_min - b_max
          //LOK: Note that t3 is being reused in this case
          tcg_gen_sub_i64(t4, t3, t2); // t4 = a_max - b_min
          tcg_gen_xor_i64(t1, t0, t4); // t1 = ((a_min - b_max)^(a_max - b_min))
          tcg_gen_or_i64(t0, arg1, arg2); // t0 = qa | qb
          tcg_gen_or_i64(arg0, t0, t1); // arg0 = (qa | qb) | ( (a_min - b_max) ^ (a_max - b_min)

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
          tcg_temp_free_i64(t3);
          tcg_temp_free_i64(t4);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

      case INDEX_op_mul_i64: // Up - mkUifU64(), mkLeft64(), mkPCastTo()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          if (arg1 && arg2) {
            // mkUifU64(arg1, arg2)
            tcg_gen_or_i64(t0, arg1, arg2);
          }
          else if (arg1) {
            tcg_gen_movi_i64(t0, arg1);
          }
          else if (arg2) {
            tcg_gen_movi_i64(t0, arg2);
          }

          // mkLeft64(t0)
          t1 = tcg_temp_new_i64();
          tcg_gen_neg_i64(t1, t0); // (-s64)
          tcg_gen_or_i64(arg0, t0, t1); // (s64 | (-s64)) -> vLo64

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_nand_i64
      case INDEX_op_nand_i64: // Special - and_or_ty()
#endif /* TCG_TARGET_HAS_nand_i64 */
      case INDEX_op_and_i64: // Special - and_or_ty()
#if TCG_TARGET_HAS_andc_i64
      case INDEX_op_andc_i64: // Special - and_or_ty()
#endif /* TCG_TARGET_HAS_andc_i64 */
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();
          t3 = tcg_temp_new_i64();
          /* T1 -> arg1
             V1 -> gen_opparam_ptr[-2]
             T2 -> arg2
             V2 -> gen_opparam_ptr[-1] */
          if (arg1) {
            tcg_gen_not_i64(t0, arg1); // NOT T1
          }
          else {
            tcg_gen_movi_i64(t0, -1);
          }
          if (arg2) {
        	  tcg_gen_and_i64(t1, orig1, arg2);//tcg_gen_and_i64(t1, gen_opparam_ptr[-2], arg2); // V1 * T2
          }
          else {
            tcg_gen_movi_i64(t1, 0);
          }
          tcg_gen_and_i64(t2, t0, t1); // (NOT T1) * V1 * T2

          if (arg2) {
            tcg_gen_not_i64(t0, arg2); // NOT T2
          }
          else {
            tcg_gen_movi_i64(t0, -1);
          }
          if (arg1) {
        	  tcg_gen_and_i64(t1, arg1, orig0);//tcg_gen_and_i64(t1, arg1, gen_opparam_ptr[-1]); // T1 * V2
          }
          else {
            tcg_gen_movi_i64(t1, 0);
          }
          tcg_gen_and_i64(t3, t0, t1); // (T1 * (NOT T2) * V2)

          if (arg1 && arg2) {
            tcg_gen_and_i64(t0, arg1, arg2); // T1 * T2
          }
          else {
            tcg_gen_movi_i64(t0, 0);
          }

          // OR it all together
          tcg_gen_or_i64(t1, t2, t3);
          tcg_gen_or_i64(arg0, t0, t1);

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
          tcg_temp_free_i64(t3);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_nor_i64
      case INDEX_op_nor_i64: // Special - and_or_ty()
#endif /* TCG_TARGET_HAS_nor_i64 */
      case INDEX_op_or_i64: // Special - and_or_ty()
#if TCG_TARGET_HAS_orc_i64
      case INDEX_op_orc_i64: // Special - and_or_ty()
#endif /* TCG_TARGET_HAS_orc_i64 */
        orig0 = gen_opparam_ptr[-3];
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          orig1 = gen_opparam_ptr[-2];
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);
            
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }

          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();
          t3 = tcg_temp_new_i64();
          /* T1 -> arg1
             V1 -> gen_opparam_ptr[-2]
             T2 -> arg2
             V2 -> gen_opparam_ptr[-1] */
          if (arg1) {
            tcg_gen_not_i64(t0, arg1); // NOT T1
          }
          else {
            tcg_gen_movi_i64(t0, -1);
          }
          tcg_gen_not_i64(t1, orig1);//tcg_gen_not_i64(t1, gen_opparam_ptr[-2]); // NOT V1
          tcg_gen_and_i64(t2, t0, t1); // (NOT T1) * (NOT V1)
          if (arg2) {
            tcg_gen_and_i64(t0, t2, arg2); // (NOT T1) * (NOT V1) * T2
          }
          else {
            tcg_gen_movi_i64(t0, 0);
          }

          if (arg2) {
            tcg_gen_not_i64(t1, arg2); // NOT T2
          }
          else {
            tcg_gen_movi_i64(t1, -1);
          }
          tcg_gen_not_i64(t2, orig0);//tcg_gen_not_i64(t2, gen_opparam_ptr[-1]); // NOT V2
          tcg_gen_and_i64(t3, t1, t2); // (NOT T2) * (NOT V2)
          if (arg1) {
            tcg_gen_and_i64(t1, t3, arg1); // (NOT T2) * (NOT V2) * T1
          }
          else {
            tcg_gen_movi_i64(t1, 0);
          }

          if (arg1 && arg2) {
            tcg_gen_and_i64(t2, arg1, arg2); // T1 * T2
          }
          else if (arg1) {
            tcg_gen_mov_i64(t2, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i64(t2, arg2);
          }

          // OR it all together
          tcg_gen_or_i64(t3, t0, t1);
          tcg_gen_or_i64(arg0, t2, t3);

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
          tcg_temp_free_i64(t3);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#else
      /* These all use the following pattern of shadow registers: */
      /* arg0 = arg1 op arg2.  To bitwise taint this pattern in shadow */
      /* registers, we use the following steps:
         Step 1: temp0 = arg1 or arg2
         Step 2: temp1 = 0
         Step 3: temp2 = (temp0 != temp1)
         Step 4: arg0 = ~temp2 */
      case INDEX_op_shl_i64:
      case INDEX_op_shr_i64:
      case INDEX_op_sar_i64:
#if TCG_TARGET_HAS_rot_i64
      case INDEX_op_rotl_i64:
      case INDEX_op_rotr_i64:
#endif /* TCG_TARGET_HAS_rot_i64 */
      case INDEX_op_add_i64:
      case INDEX_op_sub_i64:
      case INDEX_op_mul_i64:
      case INDEX_op_and_i64:
      case INDEX_op_or_i64:
#if TCG_TARGET_HAS_andc_i64
      case INDEX_op_andc_i64:
#endif /* TCG_TARGET_HAS_andc_i64 */
#if TCG_TARGET_HAS_orc_i64
      case INDEX_op_orc_i64:
#endif /* TCG_TARGET_HAS_orc_i64 */
#if TCG_TARGET_HAS_nand_i64
      case INDEX_op_nand_i64:
#endif /* TCG_TARGET_HAS_nand_i64 */
#if TCG_TARGET_HAS_nor_i64
      case INDEX_op_nor_i64:
#endif /* TCG_TARGET_HAS_nor_i64 */
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i32(arg0, 0);
            
            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();
          if (arg1) {
            tcg_gen_mov_i64(t0, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i64(t0, arg2);
          }
          else {
            tcg_gen_or_i64(t0, arg1, arg2);
          }
          tcg_gen_movi_i64(t1, 0);
          tcg_gen_setcond_i64(TCG_COND_NE, t2, t0, t1);
          tcg_gen_neg_i64(arg0, t2);

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#endif /* TCG_BITWISE_TAINT */
#if TCG_TARGET_HAS_eqv_i64
      case INDEX_op_eqv_i64: // In-Place - mkUifU64
#endif /* TCG_TARGET_HAS_eqv_i64 */
      case INDEX_op_xor_i64: // In-Place - mkUifU64
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (arg1 && arg2) {
            // Perform an OR on arg1 and arg2 to find taint
            tcg_gen_or_i64(arg0, arg1, arg2);
          }
          else if (arg1) {
            tcg_gen_mov_i64(arg0, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i64(arg0, arg2);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#if TCG_TARGET_HAS_div_i64
      case INDEX_op_div_i64: // All-around: mkLazy2()
      case INDEX_op_divu_i64: // All-around: mkLazy2()
      case INDEX_op_rem_i64: // All-around: mkLazy2()
      case INDEX_op_remu_i64: // All-around: mkLazy2()
        arg0 = find_shadow_arg(gen_opparam_ptr[-3]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg2 = find_shadow_arg(gen_opparam_ptr[-1]);

          if (!arg1 && !arg2) {
            tcg_gen_movi_i64(arg0, 0);

            // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
            break;
          }
          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();
          if (arg1) {
            tcg_gen_mov_i64(t0, arg1);
          }
          else if (arg2) {
            tcg_gen_mov_i64(t0, arg2);
          }
          else {
            tcg_gen_or_i64(t0, arg1, arg2);
          }
          tcg_gen_movi_i64(t1, 0);
          tcg_gen_setcond_i64(TCG_COND_NE, t2, t0, t1);
          tcg_gen_neg_i64(arg0, t2);

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;

#endif /* TCG_TARGET_HAS_div_i64 */
#if TCG_TARGET_HAS_div2_i64
      case INDEX_op_div2_i64: // All-around: mkLazy3()
      case INDEX_op_divu2_i64: // All-around: mkLazy3()
        arg0 = find_shadow_arg(gen_opparam_ptr[-5]);
        arg1 = find_shadow_arg(gen_opparam_ptr[-4]);
        if (arg0 && arg1) {
          arg2 = find_shadow_arg(gen_opparam_ptr[-3]);
          arg3 = find_shadow_arg(gen_opparam_ptr[-2]);
          arg4 = find_shadow_arg(gen_opparam_ptr[-1]);
          t0 = tcg_temp_new_i64();
          t1 = tcg_temp_new_i64();
          t2 = tcg_temp_new_i64();

          if (!arg2 && !arg3) {
            if (!arg4) {
              tcg_gen_movi_i64(arg0, 0);
              tcg_gen_movi_i64(arg1, 0);

              // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
              break;
            }
            tcg_gen_movi_i64(t0, 0);
          } else {
            tcg_gen_or_i32(t0, arg2, arg3);
          }
          if (arg4) {
            tcg_gen_or_i32(t2, t0, arg4);
          }
          else {
            tcg_gen_mov_i32(t2, t0);
          }

          tcg_gen_movi_i32(t1, 0);
          tcg_gen_setcond_i32(TCG_COND_NE, t0, t2, t1);
          tcg_gen_neg_i32(arg0, t0);
          tcg_gen_neg_i32(arg1, t0);

          tcg_temp_free_i64(t0);
          tcg_temp_free_i64(t1);
          tcg_temp_free_i64(t2);
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_div2_i64 */
#if TCG_TARGET_HAS_deposit_i64
      case INDEX_op_deposit_i64: // Always bitwise taint
        arg0 = find_shadow_arg(gen_opparam_ptr[-5]); // Output
        if (arg0) {
          int pos, len; // Constant parameters

          arg1 = find_shadow_arg(gen_opparam_ptr[-4]); // Input1
          arg2 = find_shadow_arg(gen_opparam_ptr[-3]); // Input2

          // Pull out the two constant parameters
          pos = gen_opparam_ptr[-2]; // Position of mask
          len = gen_opparam_ptr[-1]; // Length of mask

          // Handle special 64-bit transfer case (copy arg2 taint)
          if (len == 64) {
            if (arg2) {
              tcg_gen_mov_i64(arg0, arg2);
            }
            else {
              tcg_gen_movi_i64(arg0, 0);
            }
          // Handle special 0-bit transfer case (copy arg1 taint)
          } else if (len == 0) {
            if (arg1) {
              tcg_gen_mov_i64(arg0, arg1);
            }
            else {
              tcg_gen_movi_i64(arg0, 0);
            }
          // Handle general case
          } else {
            if (arg1 && arg2) {
              tcg_gen_deposit_tl(arg0, arg1, arg2, pos, len);
            }
            else if (arg1) {
              t0 = tcg_temp_new_i64();
              tcg_gen_movi_i64(t0, 0);
              tcg_gen_deposit_tl(arg0, arg1, t0, pos, len);
              tcg_temp_free_i64(t0);
            } else if (arg2) {
              t0 = tcg_temp_new_i64();
              tcg_gen_movi_i64(t0, 0);
              tcg_gen_deposit_tl(arg0, t0, arg2, pos, len);
              tcg_temp_free_i64(t0);
            }
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_deposit_i64 */

#if TCG_TARGET_HAS_ext8s_i64
      case INDEX_op_ext8s_i64: // MemCheck: VgT_SWiden18
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext8s_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext8s_i64 */
#if TCG_TARGET_HAS_ext16s_i64
      case INDEX_op_ext16s_i64: // MemCheck: VgT_SWiden28
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext16s_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext16s_i64 */
#if TCG_TARGET_HAS_ext32s_i64
      case INDEX_op_ext32s_i64: // MemCheck: VgT_SWiden48
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext32s_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext32s_i64 */
#if TCG_TARGET_HAS_ext8u_i64
      case INDEX_op_ext8u_i64: // MemCheck: VgT_ZWiden18
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext8u_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext8u_i64 */
#if TCG_TARGET_HAS_ext16u_i64
      case INDEX_op_ext16u_i64: // MemCheck: VgT_ZWiden28
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext16u_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext16u_i64 */
#if TCG_TARGET_HAS_ext32u_i64
      case INDEX_op_ext32u_i64: // MemCheck: VgT_ZWiden48
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_ext32u_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_ext32u_i64 */
#if TCG_TARGET_HAS_bswap16_i64
      case INDEX_op_bswap16_i64: // MemCheck: UifU2
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_bswap16_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_bswap16_i64 */
#if TCG_TARGET_HAS_bswap32_i64
      case INDEX_op_bswap32_i64: // MemCheck: UifU4
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_bswap32_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_bswap32_i64 */
#if TCG_TARGET_HAS_bswap64_i64
      case INDEX_op_bswap64_i64: // MemCheck: UifU8
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_bswap64_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_bswap64_i64 */
#if TCG_TARGET_HAS_not_i64
      case INDEX_op_not_i64: // MemCheck: nothing! Returns orig atom
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_mov_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }

        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_not_i64 */
#if TCG_TARGET_HAS_neg_i64
      case INDEX_op_neg_i64:
        arg0 = find_shadow_arg(gen_opparam_ptr[-2]);
        if (arg0) {
          arg1 = find_shadow_arg(gen_opparam_ptr[-1]);
          if (arg1) {
            tcg_gen_mov_i64(arg0, arg1);
          }
          else {
            tcg_gen_movi_i64(arg0, 0);
          }
        }

        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);

        break;
#endif /* TCG_TARGET_HAS_neg_i64 */

      /* QEMU-specific operations. */
      case INDEX_op_ld8u_i32:
      case INDEX_op_ld8s_i32:
      case INDEX_op_ld16u_i32:
      case INDEX_op_ld16s_i32:
      case INDEX_op_ld_i32:
      case INDEX_op_st8_i32:
      case INDEX_op_st16_i32:
      case INDEX_op_st_i32:
      case INDEX_op_ld8u_i64:
      case INDEX_op_ld8s_i64:
      case INDEX_op_ld16u_i64:
      case INDEX_op_ld16s_i64:
      case INDEX_op_ld32u_i64:
      case INDEX_op_ld32s_i64:
      case INDEX_op_ld_i64:
      case INDEX_op_st8_i64:
      case INDEX_op_st16_i64:
      case INDEX_op_st32_i64:
      case INDEX_op_st_i64:
        DUMMY_TAINT(nb_oargs, nb_args);
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        break; /* No taint info propagated (register liveness gets these) */
      default:
        // add_orig(&gen_op_ptr[-1], gen_opparam_ptr, nb_args);
        // fprintf(stderr, "gen_taintcheck_insn() -> UNKNOWN %d (%s)\n", opc, tcg_op_defs[opc].name);
        // fprintf(stderr, "(%s)\n", (tcg_op_defs[opc]).name);
        // assert(1==0);
        break;
    } /* End switch */

    // if (debug) {
    //   if (debug_ir_bufs_check(&tcg_ctx, gen_old_op_buf, gen_old_opparam_buf)) {
    //     assert(0);
    //   }
    // }

  } /* End taint while loop */

  global_taint_flag = 0;

  return return_lj;
#else
  return 0;
#endif /* CONFIG_TCG_TAINT */
}

int optimize_taint(CPUState *cpu) {
  // if (debug) {
  //     qemu_log_lock();
  //     qemu_log("PRE OP:\n");
  //     tcg_dump_ops(&tcg_ctx);
  //     qemu_log("\n");
  //     qemu_log_unlock();
  // }
  flag1 = 1;
  int retVal = 0;
  if (second_ccache_flag) {
    retVal = gen_taintcheck_insn();

    if (debug_taint) {
      char procname[MAX_PROCESS_NAME_LENGTH] = {0};

      uint32_t pid = 0;
      uint32_t par_pid = 0;
      target_ulong pgd = 0;
      int status = -1;

#ifdef TARGET_MIPS
      pgd = DECAF_getPGD(cpu);
      if (pgd)
        status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);
#endif
      if (pgd && !status) {
        if (!strcmp(procname, program_analysis)) {
          FILE *fp = fopen("debug/taint.log","a+");
          fprintf(fp, "POST OP:\n");
          tcg_dump_ops_2(fp, &tcg_ctx);
          fprintf(fp, "\n");
          fclose(fp);
        }
        if (!strcmp(procname, "xmldb")) {
          FILE *fp = fopen("debug/taint_xmldb.log","a+");
          fprintf(fp, "POST OP:\n");
          tcg_dump_ops_2(fp, &tcg_ctx);
          fprintf(fp, "\n");
          fclose(fp);
        }
      }
    }
  }
  else {
    retVal = gen_taintcheck_insn_ld();

    if (debug_taint) {
      char procname[MAX_PROCESS_NAME_LENGTH] = {0};

      uint32_t pid = 0;
      uint32_t par_pid = 0;
      target_ulong pgd = 0;
      int status = -1;

#ifdef TARGET_MIPS
      pgd = DECAF_getPGD(cpu);
      if (pgd)
        status = VMI_find_process_by_cr3_all(pgd, procname, 64, &pid, &par_pid);
#endif
      if (pgd && !status) {
        if (!strcmp(procname, program_analysis)) {
          FILE *fp = fopen("debug/taint.log","a+");
          fprintf(fp, "POST OP:\n");
          tcg_dump_ops_2(fp, &tcg_ctx);
          fprintf(fp, "\n");
          fclose(fp);
        }
        if (!strcmp(procname, "xmldb")) {
          FILE *fp = fopen("debug/taint_xmldb","a+");
          fprintf(fp, "POST OP:\n");
          tcg_dump_ops_2(fp, &tcg_ctx);
          fprintf(fp, "\n");
          fclose(fp);
        }
      }
    }
  }



  return(retVal);
}

#endif /* CONFIG_TCG_TAINT */

