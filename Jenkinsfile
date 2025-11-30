pipeline {
    agent any

    environment {
        IMAGES = """
            signaturedb:ragedisplay/nexuswaf-signaturedb
            analyzer:ragedisplay/nexuswaf-analyzer
            waf-admin:ragedisplay/nexuswaf-admin
            wafproxy:ragedisplay/nexuswaf-proxy
        """
        VERSION = "${env.BUILD_NUMBER}"
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

        stage('Build Images') {
            steps {
                sh 'docker compose build'
            }
        }

        stage('Tag & Push') {
            steps {
                script {

                    IMAGES.split().each { pair ->
                        def (localName, hubName) = pair.tokenize(':')

                        sh """
                            echo "Processing $localName → $hubName"

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
                    sh "mkdir -p trivy-reports"

                    IMAGES.split().each { pair ->
                        def (localName, hubName) = pair.tokenize(':')

                        sh """
                            trivy image --exit-code 0 --format table \
                                -o trivy-reports/${localName}.txt \
                                ${hubName}:latest
                        """
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/*.txt', fingerprint: true
                }
            }
        }
    }

    post {
        always { sh 'docker logout' }
    }
}
