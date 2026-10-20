-- Atomic token bucket. Redis executes a script as one indivisible unit, so concurrent requests
-- (even from many gateway instances) can never read the same token count and both succeed.
--
-- KEYS[1]  bucket key
-- ARGV[1]  capacity            (maximum tokens = burst size)
-- ARGV[2]  refill_tokens       (tokens added per period)
-- ARGV[3]  refill_period_ms    (period length in milliseconds)
-- ARGV[4]  requested           (tokens to take, normally 1)
--
-- Returns { allowed (1/0), tokens_left (integer), retry_after_ms }
--
-- Time comes from Redis (TIME), not from the gateway hosts, so gateway clock skew cannot matter.

local capacity      = tonumber(ARGV[1])
local refill_tokens = tonumber(ARGV[2])
local period_ms     = tonumber(ARGV[3])
local requested     = tonumber(ARGV[4])

local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

local data   = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts     = tonumber(data[2])

if tokens == nil or ts == nil then
  tokens = capacity
  ts = now_ms
end

local rate = refill_tokens / period_ms            -- tokens per millisecond
local elapsed = math.max(0, now_ms - ts)
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed = 0
local retry_after_ms = 0
if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
else
  retry_after_ms = math.ceil((requested - tokens) / rate)
end

redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', tostring(now_ms))
-- Expire idle buckets: time to refill completely, plus a margin.
redis.call('PEXPIRE', KEYS[1], math.ceil(capacity / rate) + 1000)

return { allowed, math.floor(tokens), retry_after_ms }
