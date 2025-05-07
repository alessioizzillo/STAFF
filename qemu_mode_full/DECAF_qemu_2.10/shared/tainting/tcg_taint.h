#ifndef __DECAF_TCG_TAINT_H__
#define __DECAF_TCG_TAINT_H__

#include <inttypes.h>
#include "tcg-op.h"

extern TCGv shadow_arg[TCG_MAX_TEMPS];
extern TCGv tempidx, tempidx2;
extern int gen_old_next_op_idx;
extern int gen_old_next_parm_idx;

extern int nb_tcg_sweeps;

extern void clean_shadow_arg(void);
extern int optimize_taint(CPUState *cpu);
extern TCGv find_shadow_arg(TCGv arg);

#endif /* __DECAF_TCG_TAINT_H__ */

