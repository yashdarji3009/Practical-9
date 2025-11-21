# Email Harvesting - Performance Optimizations

The email harvesting tool has been **significantly optimized** for speed! Here's what changed and how to use it.

## 🚀 Performance Improvements

### What Was Fixed:

1. **✅ Parallel Crawling**: Now uses multiple threads simultaneously (was sequential before)
2. **✅ Reduced Delays**: Default delay reduced from 0.5s to 0.1s per request
3. **✅ URL Limits**: Stops after processing 50 URLs by default (prevent infinite crawling)
4. **✅ Smart Prioritization**: Prioritizes email-rich pages (contact, about, team, etc.)
5. **✅ Faster Timeouts**: 5-second timeout per request (was 10 seconds)
6. **✅ Skips Unnecessary Files**: Automatically skips images, CSS, JS, PDFs, etc.
7. **✅ Progress Indicators**: Shows progress every 10 URLs
8. **✅ Better Thread Utilization**: Actually uses the threads parameter now!

## ⚡ Quick Start - Fast Modes

### Option 1: Fast Mode (Recommended)
```bash
python red_team/email_harvest.py -d example.com --fast
```
- 30 threads
- 30 URLs max
- 0.05s delay
- Depth 1 (only main pages)

**This is 10-20x faster than before!**

### Option 2: Balanced Mode (Default)
```bash
python red_team/email_harvest.py -d example.com
```
- 20 threads (default, was 10)
- 50 URLs max
- 0.1s delay
- Depth 2

### Option 3: Custom Fast Settings
```bash
# Very fast (aggressive)
python red_team/email_harvest.py -d example.com -t 50 --max-urls 30 --delay 0.05 --max-depth 1

# More thorough but still fast
python red_team/email_harvest.py -d example.com -t 30 --max-urls 100 --delay 0.1
```

## 📊 Performance Comparison

| Mode | Threads | Max URLs | Delay | Depth | Speed | Coverage |
|------|---------|----------|-------|-------|-------|----------|
| **Old Default** | 1 (sequential) | Unlimited | 0.5s | 2 | Very Slow | High |
| **Fast Mode** | 30 | 30 | 0.05s | 1 | **Very Fast** | Medium |
| **New Default** | 20 | 50 | 0.1s | 2 | **Fast** | Good |
| **Thorough** | 30 | 100 | 0.1s | 3 | Medium | High |

## 🎯 Command Options

### Basic Usage:
```bash
python red_team/email_harvest.py -d example.com
```

### All Available Options:

```bash
python red_team/email_harvest.py \
    -d example.com              # Target domain (required)
    -u https://example.com      # Starting URL (optional)
    --max-depth 2               # Crawl depth (1-3 recommended)
    -t 20                       # Number of threads (10-50 recommended)
    --max-urls 50               # Max URLs to crawl (30-100 recommended)
    --delay 0.1                 # Delay between requests in seconds
    --timeout 5                 # Request timeout in seconds
    --fast                      # Fast mode preset (recommended!)
    -o emails.txt               # Output file
```

### Recommended Settings:

**For Speed (Quick Scan):**
```bash
python red_team/email_harvest.py -d example.com --fast
```

**For Balance (Default):**
```bash
python red_team/email_harvest.py -d example.com
```

**For Thoroughness (Slower but more complete):**
```bash
python red_team/email_harvest.py -d example.com -t 30 --max-urls 100 --max-depth 3
```

## 💡 Tips for Maximum Speed

1. **Use --fast flag**: This is the easiest way to get 10-20x speed improvement
   ```bash
   python red_team/email_harvest.py -d example.com --fast
   ```

2. **Increase threads** (if your connection can handle it):
   ```bash
   python red_team/email_harvest.py -d example.com -t 50
   ```

3. **Reduce max URLs** if you only want quick results:
   ```bash
   python red_team/email_harvest.py -d example.com --max-urls 20
   ```

4. **Lower delay** for faster requests (be respectful!):
   ```bash
   python red_team/email_harvest.py -d example.com --delay 0.05
   ```

5. **Lower depth** to only crawl main pages:
   ```bash
   python red_team/email_harvest.py -d example.com --max-depth 1
   ```

## ⚠️ Important Notes

1. **Rate Limiting**: Lower delays and more threads may trigger rate limiting. If you get blocked, increase delay or reduce threads.

2. **Ethical Use**: Even with faster speeds, respect robots.txt and server limits.

3. **Network Load**: More threads = more network usage. Don't use excessive threads.

4. **Progress Updates**: The tool now shows progress every 10 URLs, so you know it's working!

## 🔧 Troubleshooting

**Problem**: Still too slow
**Solution**: Use `--fast` mode or increase threads:
```bash
python red_team/email_harvest.py -d example.com --fast
# OR
python red_team/email_harvest.py -d example.com -t 50 --max-urls 30
```

**Problem**: Getting blocked/rate limited
**Solution**: Increase delay or reduce threads:
```bash
python red_team/email_harvest.py -d example.com --delay 0.2 -t 10
```

**Problem**: Not finding enough emails
**Solution**: Increase max-urls and depth:
```bash
python red_team/email_harvest.py -d example.com --max-urls 100 --max-depth 3
```

## 📈 Expected Performance

- **Old Version**: ~5-10 URLs per minute (sequential, 0.5s delay)
- **New Default**: ~100-200 URLs per minute (20 threads, 0.1s delay)
- **Fast Mode**: ~300-600 URLs per minute (30 threads, 0.05s delay)

**Result**: Email harvesting should now complete in **seconds to minutes** instead of **minutes to hours**!

