(***********************************************************************)
(* ehandlers.ml - functions for constructing event handlers for use    *)
(*                with [Eventloop] module                              *)
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
open Eventloop
module Unix = UnixLabels

(** returns smallest floating point number larger than the argument *)
let float_incr x = x +. x *. epsilon_float

(** repeat provided callback forever, with one invocation occuring timeout
  seconds after the last one completed. *)
let repeat_forever ?(jitter=0.0) ?start timeout callback =
  let rec loop () =
    let delay = timeout +. (Random.float jitter -. jitter /. 2.) *. timeout in
    let next_time = Unix.gettimeofday () +. delay in
    [ Event (next_time, callback);
      Event (float_incr next_time, Callback loop);
    ]
  in
  let start = match start with
      None -> Unix.gettimeofday ()
    | Some time -> time
  in
  [ Event (start, Callback loop); ]


let repeat_forever_simple timeout callback =
  repeat_forever timeout (Callback (fun () -> callback (); []))
