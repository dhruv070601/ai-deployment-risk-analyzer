pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds() }
  parameters {
    booleanParam(name: 'USE_AI', defaultValue: false, description: 'Enrich rules assessment with configured AI endpoint')
    booleanParam(name: 'ALLOW_HIGH_RISK', defaultValue: false, description: 'Allow HIGH risk only after manual review')
  }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Install Python') { steps { sh '''set -eu
      python3 --version
      python3 -m venv .venv
      .venv/bin/python -m pip install --upgrade pip
      .venv/bin/python -m pip install -r requirements.txt
    ''' } }
    stage('Unit tests') { steps { sh '.venv/bin/python -m unittest discover -s tests -v' } }
    stage('Analyze deployment risk') {
      steps { script {
        if (params.USE_AI) {
          withCredentials([string(credentialsId: 'ai-api-key', variable: 'AI_API_KEY')]) {
            sh '.venv/bin/python -m risk_analyzer.analyzer --base HEAD~1 --head HEAD --out-dir reports --use-ai'
          }
        } else { sh '.venv/bin/python -m risk_analyzer.analyzer --base HEAD~1 --head HEAD --out-dir reports' }
        def report = readJSON file: 'reports/risk-report.json'
        echo "Deployment risk: ${report.risk_level} (${report.risk_score}/100)"
        if (report.risk_level == 'HIGH' && !params.ALLOW_HIGH_RISK) error('HIGH risk detected; review archived report. Deployment blocked by default.')
      } }
    }
  }
  post { always { archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true } }
}
