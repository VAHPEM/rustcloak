; Regression fixture for the virt PHI-edge bug: a PHI in a SINGLE-predecessor block reached through
; a CONDITIONAL branch. SplitAllCriticalEdges does not split that edge (the dest has one
; predecessor, so the edge is not critical), so before the fix the VM emitted no PHI copy on it and
; left the PHI's register uninitialised. clang/rustc rarely emit this shape (simplifycfg folds
; single-entry PHIs), which is why only a hand-written IR fixture catches it. Expected: g(1234)=1234,
; g(-5)=-5 (the identity, routed through %p/%r), so the process exits with (x & 0xff).
define i32 @g(i32 %a) {
entry:
  %c = icmp sgt i32 %a, 0
  br i1 %c, label %S, label %T       ; entry->S is NOT critical: S has one predecessor
S:
  %p = phi i32 [ %a, %entry ]        ; single-entry PHI reached via a conditional edge
  br label %T
T:
  %r = phi i32 [ %p, %S ], [ %a, %entry ]
  ret i32 %r
}
define i32 @main() {
  %v = call i32 @g(i32 1234)
  ret i32 %v
}
