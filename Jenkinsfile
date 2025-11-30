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
                    sh "mkdir -p trivy-reports"

                    IMAGES.split().each { mapping ->
                        def (localName, hubName) = mapping.tokenize(':')

                        sh """
                            echo "Scanning ${hubName}:latest"

                            trivy image --exit-code 0 \
                                --format table \
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
        always {
            sh 'docker logout'
        }
    }
}
