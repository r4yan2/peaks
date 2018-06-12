/***********************************************************************/
/*                                                                     */
/*                           Objective Caml                            */
/*                                                                     */
/*            Francois Rouaix, projet Cristal, INRIA Rocquencourt      */
/*                                                                     */
/*  Copyright 1996 Institut National de Recherche en Informatique et   */
/*  en Automatique.  All rights reserved.  This file is distributed    */
/*  under the terms of the GNU Library General Public License, with    */
/*  the special exception on linking described in file ../../LICENSE.  */
/*                                                                     */
/***********************************************************************/

/* $Id: dbstubs.c,v 1.1.1.1 2002/10/01 00:10:14 yminsky Exp $ */

#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/callback.h>


#include <sys/types.h>
#include <limits.h>
#include <db.h>
/* O_CREAT and others are not defined in db.h */
#include <fcntl.h>

#include <string.h>
#include "dbstubs.h"

/* This MUST be in the same order as in dbm.mli
 * We take a minimum (check O_NONBLOCK ?)
 */
static int db_open_flags[] = {
  O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC
};

/* R_IAFTER, R_IBEFORE, , R_RECNOSYNC : not relevant for btrees */
static int db_other_flags[] = {
};

/* Exception bucket for Db.error */
static value *caml_db_exn = NULL;

void raise_db(errmsg)
     char *errmsg;
{
  raise_with_string(*caml_db_exn, errmsg);
}



value caml_open_dbenv(value name) {
  DB *dbp;
  int err;

  err = db_env_create(&dbenv,0);
  if (err != 0) { printf(raise_db("db_env_create error: ")); }

  err = dbenv->open(dbenv,
                    DIRNAME,
                    DB_CREATE | DB_INIT_MPOOL,
                    S_IRUSR | S_IWUSR );
  if (err != 0) { raise_db("dbenv open error: "); }
  camldbenv {

  }

}






/* Finalisation function : occurs once at most !*/
int caml_db_close_internal(value cdb)
{
  /* close the db if needed */
  // DB_ENV dbenv;
  // DBENV->close(&dbenv,0);
  if (!Camldb_closed(cdb)) {
    Camldb_closed(cdb) = 1;
    return Camldb_db(cdb)->close(Camldb_db(cdb));
  }
  else
    return 0;
}

static void caml_db_free(value cdb)
{
  /* close the db if needed */
  caml_db_close_internal(cdb);
  /* free the structure */
  // stat_free((void *)Camldb_info(cdb));
}

/*
 * The primitives
 */
value caml_db_close(value cdb)  /* ML */
{
  if (caml_db_close_internal(cdb) == 0)
    return Val_unit;
  else
    raise_db("close");
}

value caml_db_del(value cdb, value key, value vflags) /* ML */
{
  /* Note: we could check that db is still open */
  DBT dbt;
  int flags;

  Assert(Is_string(key));
  dbt.data = String_val(key);
  dbt.size = string_length(key);
  flags = convert_flag_list(vflags, db_other_flags);

  if ( 0 == Camldb_db(cdb)->del(Camldb_db(cdb), &dbt, flags))
    return Val_unit;
  else
    raise_db("del");
}

/* fd: is said to be obsolete */
value caml_db_get(value cdb, value vkey, value vflags) /* ML */
{
  DBT key;
  DBT data;
  int flags;

  key.data = String_val(vkey);
  key.size = string_length(vkey);
  flags = convert_flag_list(vflags, db_other_flags);

  switch (Camldb_db(cdb)->get(Camldb_db(cdb), &key, &data, flags)) {
  case 0: /* success */
    {
      value res = alloc_string(data.size);
      memmove (String_val (res), data.data, data.size);
      return res;
    }
  case 1: /* not found */
    raise_not_found();
  default:
    raise_db("get");
  }
}

value caml_db_put(value cdb, value vkey, value vdata, value vflags) /* ML */
{
  DBT key;
  DBT data;
  int flags;

  key.data = String_val(vkey);
  key.size = string_length(vkey);
  data.data = String_val(vdata);
  data.size = string_length(vdata);
  flags = convert_flag_list(vflags, db_other_flags);

  switch (Camldb_db(cdb)->put(Camldb_db(cdb), &key, &data, flags)) {
  case 0: /* success */
    return Val_unit;
  case 1: /* R_NOOVERWRITE + exists */
    raise_db("Entry already exists");
  default:
    raise_db("put");
  }
}


value caml_db_seq(value cdb, value vkey, value vflags)  /* ML */
{
  DBT key;
  DBT data;
  int flags;

  key.data = String_val(vkey);
  key.size = string_length(vkey);

  flags = convert_flag_list(vflags, db_other_flags);
  switch (Camldb_db(cdb)->seq(Camldb_db(cdb), &key, &data, flags)) {
  case 0: /* success */
    {
      value reskey = Val_unit, resdata = Val_unit, res = Val_unit;
      Begin_roots3(reskey, resdata, res);
      reskey = alloc_string(key.size);
      resdata = alloc_string(data.size);
      res = alloc_small(2, 0);
      memmove (String_val (reskey), key.data, key.size);
      memmove (String_val (resdata), data.data, data.size);
      Field(res, 0) = reskey;
      Field(res, 1) = resdata;
      End_roots();
      return res;
    }
  case 1:
    raise_not_found();
  default:
    raise_db("seq");
  }
}


value caml_db_sync(value cdb)   /* ML */
{
  if (0 == Camldb_db(cdb)->sync(Camldb_db(cdb), 0))
    return Val_unit;
  else
    raise_db("sync");
}

value caml_db_open(value vfile, value vflags, value vmode, value vpars) /* ML */
{
  char *file = String_val(vfile);
  int flags = convert_flag_list(vflags, db_open_flags);
  int mode = Int_val(vmode);
  BTREEINFO *info;
  DB *db;

  /* Infos for btree structure : 0 is default everywhere */
  info = stat_alloc(sizeof(BTREEINFO));
  bzero(info, sizeof(BTREEINFO));

  while (Is_block(vpars)) {
    value par = Field(vpars, 0);
    if (Is_block(par)) { /* It's a non-constant constructor */
      switch(Tag_val(par)) {
      case 0: /* Cachesize */
        info->cachesize = Int_val(Field(par, 0));
      default:
        break;
      }
    } else { /* It's a constant constructor */
      switch (Int_val(par)) {
      case 0: /* Duplicates */
        info->flags |= R_DUP;
        break;
      default:
        break;
      }
    }
    vpars = Field(vpars, 1);
  }

  db = dbopen(file,flags,mode,DB_BTREE,info);
  if (db == NULL) {
    stat_free(info);
    raise_db("Can't open file");
  }
  else {
    /* Allocate our structure */
    value res = alloc_final(Camldb_wosize, caml_db_free, 1, Max_dballoc);
    Camldb_db(res) = db;
    Camldb_closed(res) = 0;
    // Camldb_info(res) = info;
    return res;
  }
}

/* Requires the following Caml code:
exception DBError of string
let _ = Callback.register_exception "dberror" (DBError "")
as well as a call to the init function.
*/
value caml_db_init(value v)             /* ML */
{
  if (caml_db_exn == NULL)
    caml_db_exn = caml_named_value("dberror");
  return Val_unit;
}
