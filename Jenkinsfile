pipeline {
    agent any

    environment {
        VERSION = "${env.BUILD_NUMBER}"

        IMAGES = """
            analyzer:ragedisplay/nexuswaf-analyzer
            signaturedb:ragedisplay/nexuswaf-signaturedb
            waf-admin:ragedisplay/nexuswaf-admin
            wafproxy:ragedisplay/nexuswaf-proxy
        """
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Docker Login') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'dockerhub',
                    usernameVariable: 'USER',
                    passwordVariable: 'PASS'
                )]) {
                    sh 'echo "$PASS" | docker login -u "$USER" --password-stdin'
                }
            }
        }

        stage('Build Docker Images') {
            steps {
                sh 'docker compose build'
            }
        }

        stage('Tag & Push Images') {
            steps {
                script {
                    IMAGES.split().each { mapping ->
                        def (localName, hubName) = mapping.tokenize(':')

                        sh """
                            echo "Tagging $localName as $hubName"

                            docker tag ${localName}:latest ${hubName}:${VERSION}
                            docker tag ${localName}:latest ${hubName}:latest

                            docker push ${hubName}:${VERSION}
                            docker push ${hubName}:latest
                        """
                    }
                }
            }
        }

stage('Trivy Scan') {
  steps {
    script {
      sh '''
      set -e

      # ensure trivy binary (not snap). If trivy not installed, download latest binary.
      if ! command -v trivy >/dev/null 2>&1; then
        echo "Installing trivy..."
        curl -sSfL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s)_64.tar.gz -o /tmp/trivy.tar.gz || true
        mkdir -p /tmp/trivy-bin
        tar -xzf /tmp/trivy.tar.gz -C /tmp/trivy-bin || true
        sudo mv /tmp/trivy-bin/trivy /usr/local/bin/trivy || true
      fi

      export TRIVY_CACHE_DIR=/tmp/trivy-cache
      mkdir -p ${WORKSPACE}/trivy-reports ${TRIVY_CACHE_DIR}

      # images to scan - use the pushed DockerHub names (so scan same image as produced)
      IMAGES="${IMAGES_RAW}"   
      for img in $IMAGES; do
        safe=$(echo $img | sed 's/[:/]/_/g')
        echo "Scanning $img -> trivy-reports/${safe}.json"
        # json report (detailed)
        trivy image --security-checks vuln,config --format json -o ${WORKSPACE}/trivy-reports/${safe}.json $img || true
        # also generate small human-readable table
        trivy image --security-checks vuln --format table -o ${WORKSPACE}/trivy-reports/${safe}.txt $img || true
      done
      '''
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'trivy-reports/*', fingerprint: true
      publishHTML (target: [
         allowMissing: true,
         alwaysLinkToLastBuild: true,
         keepAll: true,
         reportDir: 'trivy-reports',
         reportFiles: 'index.html',
         reportName: 'Trivy Reports'
      ]) // optional
    }
  }
}

    post {
        always {
            sh 'docker logout'
        }
    }
}
