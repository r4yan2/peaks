(***********************************************************************)
(* wserver.ml - simple web server code                                 *)
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

open StdLabels
open MoreLabels
open Printf
open Common
module Unix = UnixLabels
open Unix

module Map = PMap.Map
module Set = PSet.Set

(*exception Page_not_found of string
exception No_results of string
exception Not_implemented of string
exception Bad_request of string
exception Entity_too_large of string
exception Misc_error of string*)

let ( |= ) map key = Map.find key map
let ( |< ) map (key,data) = Map.add ~key ~data map

let stripchars = Set.of_list [ ' '; '\t'; '\n'; '\r' ]

let strip s =
  let start = ref 0 in
  while (!start < BytesLabels.length s
         && Set.mem s.[!start] stripchars) do
    incr start
  done;
  let stop = ref (BytesLabels.length s - 1) in
  while (!stop >= 0 && Set.mem s.[!stop] stripchars) do
    decr stop
  done;
  if !stop >= !start then
    BytesLabels.sub s ~pos:!start ~len:(!stop - !start + 1)
  else
    ""

let is_blank line =
  BytesLabels.length line = 0 || line.[0] = '\r'

let rec parse_headers map cin =
  let line = input_line cin in (* DoS attack: input_line is unsafe on sockets *)
  if is_blank line then map
  else
    let colonpos = try BytesLabels.index line ':' with
        Not_found -> failwith "Error parsing headers: no colon found"
    in
    let key = BytesLabels.sub line ~pos:0 ~len:colonpos
    and data = BytesLabels.sub line ~pos:(colonpos + 1)
                 ~len:(BytesLabels.length line - colonpos - 1)
    in
    parse_headers (map |< (BytesLabels.lowercase key, strip data)) cin
