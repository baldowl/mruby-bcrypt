/*
** mrb_bcrypt_engine.c - BCrypt::Engine class
**
** See Copyright Notice in LICENSE
*/

#include "mruby.h"
#include "crypt_blowfish/ow-crypt.h"
#include "mruby/string.h"
#include <string.h>
#include <sys/errno.h>
#include <stdlib.h>

/*
 * call-seq:
 *    BCrypt::Engine.__bc_salt(prefix_string, cost, random_string)    -> string
 */
static mrb_value bc_salt(mrb_state *mrb, mrb_value self){
	mrb_value prefix, input, str_salt;
	mrb_int count;
	char *salt;

	mrb_get_args(mrb, "SiS", &prefix, &count, &input);

	salt = crypt_gensalt_ra(RSTRING_PTR(prefix), count,
	    RSTRING_PTR(input), RSTRING_LEN(input));

	if (!salt) mrb_raise(mrb, E_RUNTIME_ERROR, strerror(errno));

	str_salt = mrb_str_new_cstr(mrb, salt);
	free(salt);

	return str_salt;
}



/*
 * call-seq:
 *    BCrypt::Engine.hash_secret(secret, salt)    -> hashed_string
 */
static mrb_value bc_crypt(mrb_state *mrb, mrb_value self){
	mrb_value key, settings, hashed_key;
	char *hashed;

	void *data = NULL;
	int size = 0xDEADBEEF;

	mrb_get_args(mrb, "SS", &key, &settings);

	hashed = crypt_ra(RSTRING_PTR(key), RSTRING_PTR(settings), &data,
	    &size);

	if (!hashed) mrb_raise(mrb, E_RUNTIME_ERROR, strerror(errno));

 	hashed_key= mrb_str_new(mrb, hashed, size - 1);
	free(data);

	return hashed_key;
}



void bcrypt_engine_init(mrb_state *mrb, struct RClass *module){
	struct RClass *engine;

	engine = mrb_define_class_under(mrb, module, "Engine", mrb->object_class);

	mrb_define_class_method(mrb, engine, "__bc_salt", bc_salt, MRB_ARGS_REQ(3));
	mrb_define_class_method(mrb, engine, "hash_secret", bc_crypt, MRB_ARGS_REQ(2));
}
