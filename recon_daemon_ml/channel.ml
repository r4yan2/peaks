(***********************************************************************)
(* channel.ml                                                          *)
(*                                                                     *)
(* Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, *)
(*               2011, 2012, 2013  Yaron Minsky and Contributors       *)
(*                                                                     *)
(* This file is part of SKS.  SKS is free software; you can            *)
(* redistribute it and/or modify it under the terms of the GNU General *)
(* Public License as published by the Free Software Foundation; either *)
(* version 2 of the License, or (at your option) any later version.    *)
(*                                                                     *)
(* This program is distributed in the hope that it will be useful, but *)
(* WITHOUT ANY WARRANTY; without even the implied warranty of          *)
(* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU   *)
(* General Public License for more details.                            *)
(*                                                                     *)
(* You should have received a copy of the GNU General Public License   *)
(* along with this program; if not, write to the Free Software         *)
(* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 *)
(* USA or see <http://www.gnu.org/licenses/>.                          *)
(***********************************************************************)

open BytesLabels
open MoreLabels
open Common
module Unix=UnixLabels

(******************************************************************)

let char_width = 8
let int_size = 4
let int32_size = 4
let int64_size = 8

let byte64 = Int64.of_int 0xFF
let byte32 = Int32.of_int 0xFF

(** creates function for reading strings that is safe for use with
  non-blocking channels *)
let create_nb_really_input inchan =
  let stringopt = ref None
  and pos = ref 0
  in
  let input len =
    let string =
      match !stringopt with
          None ->
            let string = BytesLabels.create len in
            stringopt := Some string;
            pos := 0;
            string
        | Some string -> string
    in
    if BytesLabels.length string <> len then
      failwith ("create_nb_really_input: attempt to redo incomplete " ^
                "read with different size");

    (* try to read all remaining bytes *)
    begin
      try
        while !pos < len do
          let r = input inchan string !pos (len - !pos) in
          if r = 0 then (raise End_of_file)
          else pos := !pos + r
        done
      with
        | Unix.Unix_error (Unix.EAGAIN,_,_)
        | Unix.Unix_error (Unix.EWOULDBLOCK,_,_)
        | Sys_blocked_io ->
            raise Sys_blocked_io
    end;

    (* if we get here, then read was complete *)
    stringopt := None;
    string
  in
  input

let read_binary_int64_internal cin ~size =
  let intbuf = cin#read_string size in
  let value = ref Int64.zero in
  for i = 0 to size - 1 do
    value := Int64.add (Int64.shift_left !value char_width)
      (Int64.of_int (int_of_char intbuf.[i]))
  done;
  !value

let read_binary_int32_internal cin ~size =
  let intbuf = cin#read_string size in
  let value = ref Int32.zero in
  for i = 0 to size - 1 do
    value := Int32.add (Int32.shift_left !value char_width)
      (Int32.of_int (int_of_char intbuf.[i]))
  done;
  !value

let read_binary_int_internal cin ~size =
  let intbuf = cin#read_string size in
  let value = ref 0 in
  for i = 0 to size - 1 do
    value := (!value lsl char_width) + (int_of_char intbuf.[i])
  done;
  !value

(***********************************************************************)

let rec read_all_rec cin sbuf buf =
  let status = input cin sbuf 0 (String.length sbuf) in
    if status = 0 then ()
    else (
      Buffer.add_substring buf sbuf 0 status;
      read_all_rec cin sbuf buf
    )

let read_all cin ?len ()=
  let len = match len with
      None -> 1024 * 100
    | Some x -> x
  in
  let sbuf = BytesLabels.create len
  and buf = Buffer.create len in
    read_all_rec cin sbuf buf;
    Buffer.contents buf

(*********************************************************************)

class virtual out_channel_obj =
object (self)
  method upcast = (self :> out_channel_obj)

  method write_int x =
    self#write_byte (0xFF land (x lsr 24));
    self#write_byte (0xFF land (x lsr 16));
    self#write_byte (0xFF land (x lsr 8));
    self#write_byte (0xFF land (x lsr 0))
  method virtual write_string : string -> unit
  method virtual write_string_pos : buf:string -> pos:int -> len:int -> unit
  method virtual write_char : char -> unit
  method virtual write_byte : int -> unit
  method write_int32 x =
    for i = int32_size - 1 downto 0 do
      let shifted = (Int32.shift_right_logical x (i * 8) ) in
      self#write_byte (Int32.to_int (Int32.logand byte32 shifted))
    done
  method write_int64 x =
    for i = int64_size - 1 downto 0 do
      let shifted = (Int64.shift_right_logical x (i * 8) ) in
      self#write_byte (Int64.to_int (Int64.logand byte64 shifted))
    done
  method write_float x =
    let bits = Int64.bits_of_float x in
    self#write_int64 bits
end

class virtual in_channel_obj =
object (self)
  method upcast = (self :> in_channel_obj)

  method virtual read_string_pos : buf:string -> pos:int -> len:int -> unit
  method virtual read_char : char
  method read_string len =
    let buf = BytesLabels.create len in
    self#read_string_pos ~buf ~pos:0 ~len;
    buf
  method read_byte = int_of_char self#read_char
  method read_int_size size = read_binary_int_internal self ~size
  method read_int = read_binary_int_internal self ~size:int_size
  method read_int32 = read_binary_int32_internal self ~size:int32_size
  method read_int64 = read_binary_int64_internal self ~size:int64_size
  method read_int64_size size = read_binary_int64_internal self ~size
  method read_float =
    let bits = read_binary_int64_internal self ~size:int64_size in
    Int64.float_of_bits bits
end

(****************************************************)


class sys_out_channel cout =
object (self)
  inherit out_channel_obj
  method flush = flush cout
  method close = close_out cout
  method write_string str = output_string cout str
  method write_string_pos ~buf ~pos ~len= output cout buf pos len
  method write_char char = output_char cout char
  method write_byte byte = output_byte cout byte
  method write_buf buf = Buffer.output_buffer cout buf

  method outchan = cout
  method fd = Unix.descr_of_out_channel cout
  method skip n =
    let skipped = Unix.lseek self#fd n ~mode:Unix.SEEK_CUR in
    if skipped <> n then raise End_of_file

  initializer
    set_binary_mode_out cout true
end

(****************************************************)

class sys_in_channel cin =
  let input = create_nb_really_input cin in
object (self)
  inherit in_channel_obj

  method close = close_in cin
  method read_all = read_all cin ()
  method read_string len = input len
  method read_string_pos ~buf ~pos ~len =
    let s = input len in
    BytesLabels.blit ~src:s ~dst:buf ~src_pos:0 ~dst_pos:pos ~len

  method read_char =
    input_char cin

  method inchan = cin
  method fd = Unix.descr_of_in_channel cin

  initializer
    set_binary_mode_in cin true
end

(****************************************************)

class buffer_out_channel buf =
object (self)
  inherit out_channel_obj

  method contents = Buffer.contents buf
  method buffer_nocopy = buf

  method write_string str = Buffer.add_string buf str
  method write_string_pos ~buf:string ~pos ~len =
    Buffer.add_substring buf string pos len
  method write_char char = Buffer.add_char buf char
  method write_byte byte = Buffer.add_char buf (char_of_int (0xFF land byte))
end


(****************************************************)

class string_in_channel string pos =
object (self)
  inherit in_channel_obj

  val slength = String.length string
  val mutable pos = pos

  method read_string len =
    if pos + len > slength then raise End_of_file;
    let rval = BytesLabels.sub string ~pos ~len in
      pos <- pos + len;
      rval

  method read_rest =
    if pos >= slength then ""
    else
      let rval = BytesLabels.sub string ~pos ~len:(slength - pos) in
      pos <- slength;
      rval

  method read_string_pos ~buf ~pos:dst_pos ~len =
    if pos + len > slength then raise End_of_file;
    BytesLabels.blit ~src:string ~src_pos:pos
      ~dst:buf ~dst_pos ~len;
    pos <- pos + len

  method read_char =
    if pos + 1 > slength then raise End_of_file;
    let char = string.[pos] in
      pos <- pos + 1;
      char

  method read_byte =
    if pos + 1 > slength then raise End_of_file;
    let byte = int_of_char string.[pos] in
      pos <- pos + 1;
      byte

  method skip bytes =
    if pos + bytes > slength then raise End_of_file;
    pos <- pos + bytes

end



let new_buffer_outc size = new buffer_out_channel (Buffer.create size)
let sys_out_from_fd fd = new sys_out_channel (Unix.out_channel_of_descr fd)
let sys_in_from_fd fd = new sys_in_channel (Unix.in_channel_of_descr fd)
let sys_out_of_fd fd = sys_out_from_fd
let sys_in_of_fd fd = sys_in_from_fd
