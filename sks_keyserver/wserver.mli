val stripchars : char PSet.Set.t
val strip : string -> string
val is_blank : string -> bool
val parse_headers :
  (string, string) PMap.Map.t -> in_channel -> (string, string) PMap.Map.t