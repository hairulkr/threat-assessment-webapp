# Cybersecurity Threat Assessment Web App

A Streamlit-based web application for automated cybersecurity threat modeling and risk assessment.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables
Create a `.env` file with your API keys:
```
GEMINI_API_KEY=your_gemini_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
GOOGLE_CSE_ID=your_google_cse_id_here
```

### 3. Run the Web App
```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

## 🌟 Features

- **Web Interface**: User-friendly Streamlit interface
- **Real-time Progress**: Live progress tracking during assessment
- **Threat Intelligence**: Multi-source threat data gathering
- **AI Analysis**: LLM-powered risk assessment and MITRE mapping
- **Professional Reports**: HTML reports with download capability
- **No Storage Required**: In-memory processing for demos

## 🛡️ Assessment Process

1. **Product Analysis** - Identifies components and technologies
2. **Threat Intelligence** - Gathers CVE data from NVD and other sources
3. **Web Intelligence** - Enriches with additional threat context
4. **Risk Assessment** - Maps threats to MITRE ATT&CK framework
5. **Security Controls** - Proposes mitigation strategies
6. **Expert Review** - Validates data quality and confidence

## 📊 Output

- Interactive web dashboard
- Professional HTML reports
- Threat summary cards
- Download capability for offline viewing

## 🔧 Configuration

### Required API Keys:
- **GEMINI_API_KEY**: For AI analysis (required)
- **SHODAN_API_KEY**: For exposure intelligence (optional)
- **GOOGLE_API_KEY**: For exploit database search (optional)

### Optional Settings:
- Modify agent parameters in respective files
- Customize report styling in `app.py`
- Adjust threat intelligence sources in `threat_intel_sources.py`

## 🚀 Deployment

### Streamlit Cloud (Free)
1. Push to GitHub repository
2. Connect to Streamlit Cloud
3. Add environment variables in Streamlit Cloud settings
4. Deploy with one click

### Local Docker
```bash
docker build -t threat-assessment-app .
docker run -p 8501:8501 threat-assessment-app
```

## 📝 Usage Examples

- **Software Products**: "Visual Studio Code", "Apache Tomcat"
- **Frameworks**: "React", "Django", "Spring Boot"
- **Infrastructure**: "Docker", "Kubernetes", "nginx"

## 🔒 Security Notes

- API keys are loaded from environment variables
- No data persistence (demo mode)
- All processing happens in memory
- Reports are generated client-side

## 🤝 Contributing

This is a demo/POC version. For production deployment:
- Add user authentication
- Implement data persistence
- Add caching layers
- Scale with containerization

## 📄 License

Internal use only - Cybersecurity threat assessment tool.