pipeline {
    agent any

    environment {
        DOCKERHUB_REPO = "ragedisplay"   
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
                withCredentials([usernamePassword(credentialsId: 'dockerhub',
                                                 usernameVariable: 'DOCKER_USER',
                                                 passwordVariable: 'DOCKER_PASS')]) {
                    sh """
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                    """
                }
            }
        }

        stage('Build Images') {
            steps {
                sh """
                    docker compose build
                """
            }
        }

        stage('Tag & Push Images') {
            steps {
                script {
                    def services = ["nexuswaf-analyzer", "nexuswaf-signaturedb", "nexuswaf-proxy", "nexuswaf-admin"]

                    services.each { svc ->
                        sh """
                            docker tag ${svc}:latest ${DOCKERHUB_REPO}/${svc}:${VERSION}
                            docker tag ${svc}:latest ${DOCKERHUB_REPO}/${svc}:latest
                            docker push ${DOCKERHUB_REPO}/${svc}:${VERSION}
                            docker push ${DOCKERHUB_REPO}/${svc}:latest
                        """
                    }
                }
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    sh "mkdir -p trivy-reports"
                    def services = ["nexuswaf-analyzer", "nexuswaf-signaturedb", "nexuswaf-proxy", "nexuswaf-admin"]

                    services.each { svc ->
                        sh """
                            trivy image --exit-code 0 --format table \
                            -o trivy-reports/${svc}.txt \
                            ${DOCKERHUB_REPO}/${svc}:latest
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
            sh "docker logout"
        }
    }
}
