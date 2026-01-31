# Agent BLACK - Evolution & Learning System

## How Agent BLACK Learns

Agent BLACK evolves through **experience capture** - recording what worked, 
what failed, and why during each engagement.

### Knowledge Sources

1. **Static Knowledge** (pre-loaded)
   - `modules.json` - LANTERN scanning modules
   - `chains.json` - Pre-defined attack chains
   - `presets.json` - Scan configurations

2. **Dynamic Knowledge** (grows with experience)
   - `lessons_learned.json` - Captured insights from engagements
   - Attack chains that worked
   - Failed attempts and alternatives
   - Target signatures and fingerprints

### Learning Loop

```
     ┌─────────────────┐
     │   New Target    │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │ Check Lessons   │◄──── lessons_learned.json
     │ Learned DB      │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │ Plan Attack     │◄──── Use past successes
     │ (Skip failures) │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │ Execute Attack  │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │ Capture Results │
     └────────┬────────┘
              ▼
     ┌─────────────────┐
     │ Update Lessons  │────► lessons_learned.json
     │ Learned DB      │
     └─────────────────┘
```

### What Gets Captured

For each engagement:

1. **Successful Techniques**
   - What worked
   - Why it worked
   - How to replicate

2. **Failed Attempts**
   - What didn't work
   - Why it failed
   - Alternatives tried

3. **Target Signatures**
   - How to identify similar targets
   - Default credentials
   - Known vulnerable endpoints

4. **Attack Chains**
   - Step-by-step sequences
   - Success rates
   - Stealth ratings

### Example: OMV Learning

Before OMV engagement:
- Agent BLACK knew generic web attacks
- No specific OMV knowledge

After OMV engagement:
- Knows OMV default creds: admin:openmediavault
- Knows API endpoint: /rpc.php
- Knows UserMgmt.setUser creates system users
- Knows to check Ssh.get for root login status
- Learned backdoor user > brute-force (stealthier)

### Future Improvements

1. **Auto-capture** - Automatically log all API calls and results
2. **Pattern Recognition** - Identify similar targets automatically
3. **Strategy Evolution** - Prioritize techniques by success rate
4. **Cross-target Learning** - Apply lessons from one NAS to all NAS devices
