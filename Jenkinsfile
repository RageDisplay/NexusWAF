pipeline {
    agent any

    environment {
        DOCKERHUB_CREDENTIALS = credentials('dockerhub')
        REGISTRY = "docker.io/ragedisplay"
        VERSION = "v1.0.${BUILD_NUMBER}"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build & Push Images from Compose') {
            steps {
                script {
                    def compose = readYaml file: 'docker-compose.yml'
                    compose.services.each { name, config ->
                        
                        def imageName = "${REGISTRY}/${name}"

                        sh """
                        docker build -t ${imageName}:${VERSION} ${config.build ?: "."}
                        docker tag ${imageName}:${VERSION} ${imageName}:latest

                        echo "${DOCKERHUB_CREDENTIALS_PSW}" | docker login -u "${DOCKERHUB_CREDENTIALS_USR}" --password-stdin

                        docker push ${imageName}:${VERSION}
                        docker push ${imageName}:latest
                        """
                    }
                }
            }
        }

        stage('Deploy to Kubernetes') {
            when {
                expression { fileExists('k8s') }
            }
            steps {
                script {
                    sh """
                    kubectl apply -f k8s/
                    """
                }
            }
        }
    }
}
