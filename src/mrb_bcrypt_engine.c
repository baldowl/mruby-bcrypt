/*
** mrb_bcrypt_engine.c - BCrypt::Engine class
**
** See Copyright Notice in LICENSE
*/

#include "mruby.h"

#if defined __APPLE__ && ((defined __MAC_OS_X_VERSION_MIN_REQUIRED && __MAC_OS_X_VERSION_MIN_REQUIRED >= 101000) || (defined __IPHONE_OS_VERSION_MIN_REQUIRED && __IPHONE_OS_VERSION_MIN_REQUIRED >= 80000))
#define _MRUBY_BCRYPT_USES_COMMON_CRYPTO
#endif

#ifdef _MRUBY_BCRYPT_USES_COMMON_CRYPTO
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonRandom.h>
#include <sys/errno.h>
#include <stdlib.h>
#else
#include <openssl/rand.h>
#include <openssl/err.h>
#endif
#include <string.h>

/*
 * call-seq:
 *    BCrypt::Engine.__bc_random_bytes(int)    -> string
 */
static mrb_value bc_random_bytes(mrb_state *mrb, mrb_value self){
	mrb_int len, buffer_size;
	unsigned char *buf;
	mrb_value rand_str;

	mrb_get_args(mrb, "i", &len);
	if (len < 0) mrb_raise(mrb, E_ARGUMENT_ERROR, "illegal string size");

	buffer_size = len + 1;

	buf = (unsigned char *)mrb_malloc(mrb, buffer_size);
	memset(buf, 0, buffer_size);

#ifdef _MRUBY_BCRYPT_USES_COMMON_CRYPTO
	if (CCRandomGenerateBytes(buf, len) != kCCSuccess){
		mrb_raise(mrb, E_RUNTIME_ERROR, "Unable to generate random numbers");
	}
#else
	if (RAND_bytes(buf, len) != 1){
		char error_message[120];
		ERR_error_string(ERR_get_error(), error_message);
		mrb_raise(mrb, E_RUNTIME_ERROR, error_message);
	}
#endif

	rand_str = mrb_str_new(mrb, (const char *)buf, len);
	mrb_free(mrb, buf);

	return rand_str;
}



#include "crypt_blowfish/ow-crypt.h"
#include "mruby/string.h"

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
	mrb_int size = 0xDEADBEEF;

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

	mrb_define_class_method(mrb, engine, "__bc_random_bytes", bc_random_bytes, MRB_ARGS_REQ(1));
	mrb_define_class_method(mrb, engine, "__bc_salt", bc_salt, MRB_ARGS_REQ(3));
	mrb_define_class_method(mrb, engine, "hash_secret", bc_crypt, MRB_ARGS_REQ(2));
}
