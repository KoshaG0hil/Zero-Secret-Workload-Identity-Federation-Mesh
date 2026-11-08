output "oidc_provider_arn" {
  description = "ARN of the IAM OpenID Connect Provider"
  value       = aws_iam_openid_connect_provider.identity_mesh.arn
}

output "federated_role_arn" {
  description = "ARN of the IAM role assumed via Web Identity"
  value       = aws_iam_role.federated_workload_role.arn
}

output "spiffe_identity_bound" {
  description = "SPIFFE URI strictly bound in the IAM role trust policy"
  value       = "spiffe://${var.trust_domain}/ns/${var.target_namespace}/sa/${var.target_service_account}"
}
