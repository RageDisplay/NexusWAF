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

        stage('Trivy Scan (non-blocking)') {
            steps {
                script {
                    // Prepare workspace-local trivy and cache to avoid snap & HOME problems
                    sh '''
                    set -eux

                    export TRIVY_WORK_DIR="${WORKSPACE}/.trivy"
                    export TRIVY_BIN="${WORKSPACE}/bin/trivy"
                    export PATH="${WORKSPACE}/bin:$PATH"
                    mkdir -p "${WORKSPACE}/bin" "${TRIVY_WORK_DIR}" "${WORKSPACE}/trivy-reports"

                    # If trivy binary is not available, download portable tarball into workspace/bin
                    if ! command -v trivy >/dev/null 2>&1; then
                      echo "Trivy not found in PATH — downloading local trivy to ${WORKSPACE}/bin ..."
                      TMPTGZ="/tmp/trivy_$$.tar.gz"
                      curl -sSfL "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s)_64.tar.gz" -o "${TMPTGZ}" || true
                      tar -xzf "${TMPTGZ}" -C "${WORKSPACE}/bin" trivy || true
                      chmod +x "${WORKSPACE}/bin/trivy" || true
                    fi

                    # ensure we have a trivy binary in PATH now (local one or system)
                    if ! command -v trivy >/dev/null 2>&1; then
                      echo "ERROR: trivy binary is not available; skipping scans but not failing the build."
                      exit 0
                    fi

                    export TRIVY_CACHE_DIR="${TRIVY_WORK_DIR}/cache"
                    mkdir -p "${TRIVY_CACHE_DIR}" "${WORKSPACE}/trivy-reports"

                    # Loop images and create JSON + human-readable table reports.
                    IMAGES_RAW=''' + "'''${IMAGES}'''" + '''
                    for mapping in ${IMAGES_RAW}; do
                      # mapping = local:hub
                      hub=$(echo ${mapping} | cut -d: -f2)
                      # sanitize name for filenames
                      safe=$(echo ${hub} | sed 's/[:/]/_/g')
                      echo "Scanning ${hub}:latest -> trivy-reports/${safe}.json and .txt"

                      # JSON detailed report (do not fail if trivy returns non-zero): store as json
                      trivy image --cache-dir "${TRIVY_CACHE_DIR}" --format json -o "${WORKSPACE}/trivy-reports/${safe}.json" "${hub}:latest" || true

                      # Human-readable table (also don't fail)
                      trivy image --cache-dir "${TRIVY_CACHE_DIR}" --format table -o "${WORKSPACE}/trivy-reports/${safe}.txt" "${hub}:latest" || true
                    done
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/*', fingerprint: true
                }
            }
        }
    }

    post {
        always {
            sh 'docker logout || true'
        }
    }
}
