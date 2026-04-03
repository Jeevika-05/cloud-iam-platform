--[[
  atomicRiskUpdate.lua
  ─────────────────────────────────────────────────────────────────────────────
  Atomically updates a risk entity's state in Redis.
  Replaces the non-atomic MULTI pipeline read-modify-write pattern.

  KEYS[1]  = risk:state:<entity>   (JSON blob: {score, timestamp})
  KEYS[2]  = risk:window:<entity>:<slot>  (hash of event counts)
  KEYS[3]  = risk:sequence:<entity>       (list of last 5 event types)

  ARGV[1]  = eventType            (string, e.g. "LOGIN_FAILED")
  ARGV[2]  = eventTimeMs          (number as string)
  ARGV[3]  = windowTTL            (seconds, e.g. "600")
  ARGV[4]  = sequenceTTL          (seconds, e.g. "3600")
  ARGV[5]  = stateTTL             (seconds, e.g. "86400")

  Returns a Redis array (Lua table):
    [1] hincrbyCount  — count of this eventType in the current window
    [2] previousScore — score from last state (0 if none)
    [3] lastTime      — timestamp from last state (eventTimeMs if none)
    [4] seqJSON       — JSON array string of up to 5 recent event types
  ─────────────────────────────────────────────────────────────────────────────
--]]

local stateKey    = KEYS[1]
local windowKey   = KEYS[2]
local sequenceKey = KEYS[3]

local eventType   = ARGV[1]
local eventTimeMs = tonumber(ARGV[2])
local windowTTL   = tonumber(ARGV[3])
local sequenceTTL = tonumber(ARGV[4])
local stateTTL    = tonumber(ARGV[5])

-- 1. Increment window count for this event type (atomic HINCRBY)
local hincrbyCount = redis.call('HINCRBY', windowKey, eventType, 1)
redis.call('EXPIRE', windowKey, windowTTL)

-- 2. Prepend event type to sequence list, trim to last 5
redis.call('LPUSH', sequenceKey, eventType)
redis.call('LTRIM', sequenceKey, 0, 4)
redis.call('EXPIRE', sequenceKey, sequenceTTL)

-- 3. Read existing state (score + timestamp) atomically
local stateRaw = redis.call('GET', stateKey)
local previousScore = 0
local lastTime = eventTimeMs

if stateRaw then
  -- Safe JSON decode: only read fields we need to avoid injection
  local score = string.match(stateRaw, '"score"%s*:%s*([%d%.%-]+)')
  local ts    = string.match(stateRaw, '"timestamp"%s*:%s*([%d%.%-]+)')
  if score then previousScore = tonumber(score) or 0 end
  if ts    then lastTime = tonumber(ts) or eventTimeMs end
end

-- 4. Read the sequence list
local seqList = redis.call('LRANGE', sequenceKey, 0, 4)

-- Encode sequence as a simple JSON array string
local seqParts = {}
for i, v in ipairs(seqList) do
  seqParts[i] = '"' .. v .. '"'
end
local seqJSON = '[' .. table.concat(seqParts, ',') .. ']'

-- Clamp lastTime to not be in the future relative to eventTimeMs
if lastTime > eventTimeMs then lastTime = eventTimeMs end

return {
  hincrbyCount,
  previousScore,
  lastTime,
  seqJSON
}
