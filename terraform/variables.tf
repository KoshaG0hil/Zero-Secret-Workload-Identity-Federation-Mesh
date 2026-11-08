variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "trust_domain" {
  type        = string
  description = "SPIFFE trust domain"
  default     = "prod.aws.internal"
}

variable "oidc_issuer_url" {
  type        = string
  description = "URL of the OIDC identity mesh discovery provider"
  default     = "https://oidc.identity.mesh.internal"
}

variable "oidc_client_id" {
  type        = string
  description = "Expected audience for STS AssumeRoleWithWebIdentity"
  default     = "sts.amazonaws.com"
}

variable "oidc_thumbprint" {
  type        = string
  description = "SHA-1 thumbprint of the OIDC server's root certificate"
  default     = "9e99a48a9960b14926cc7f3b02e22da2b0ab7280"
}

variable "workload_name" {
  type        = string
  description = "Name of the target microservice"
  default     = "payment-service"
}

variable "target_namespace" {
  type        = string
  description = "Kubernetes namespace where workload executes"
  default     = "prod"
}

variable "target_service_account" {
  type        = string
  description = "Kubernetes Service Account attached to the pod"
  default     = "payment-service"
}
