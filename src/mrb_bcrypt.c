/*
** mrb_bcrypt.c - BCrypt module
**
** See Copyright Notice in LICENSE
*/

#include "mruby.h"
#include "mrb_bcrypt.h"
#include "mrb_bcrypt_engine.h"

void mrb_mruby_bcrypt_gem_init(mrb_state *mrb){
	struct RClass *bcrypt;
	bcrypt = mrb_define_module(mrb, "BCrypt");
	bcrypt_engine_init(mrb, bcrypt);
}

void mrb_mruby_bcrypt_gem_final(mrb_state *mrb){}
