# Security Guidelines

## 🔒 Deployment Security

### Required Environment Variables
Set these in Streamlit Cloud secrets (NOT in code):
```
GEMINI_API_KEY=your_actual_key
APP_PASSWORD=strong_password_here
```

### Security Features
- ✅ Password authentication with brute force protection
- ✅ Rate limiting (30s cooldown between assessments)  
- ✅ Daily usage quotas (10 assessments per day)
- ✅ Input validation and sanitization
- ✅ Content Security Policy headers
- ✅ No data persistence (session-based only)

### Deployment Checklist
- [ ] Set strong APP_PASSWORD in Streamlit secrets
- [ ] Add GEMINI_API_KEY to Streamlit secrets
- [ ] Verify .env file is NOT committed to repo
- [ ] Test authentication and rate limiting
- [ ] Monitor usage logs

## ⚠️ Important Notes
- This repo is PUBLIC - never commit API keys or passwords
- Use Streamlit Cloud secrets for all sensitive data
- Change default passwords before deployment
- Monitor for unauthorized access attempts