terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. AWS IAM OpenID Connect Provider for Identity Mesh
resource "aws_iam_openid_connect_provider" "identity_mesh" {
  url             = var.oidc_issuer_url
  client_id_list  = [var.oidc_client_id]
  thumbprint_list = [var.oidc_thumbprint]

  tags = {
    Environment = var.environment
    ManagedBy   = "ZeroSecret-Identity-Mesh"
    Architecture = "Workload-Identity-Federation"
  }
}

# 2. IAM Role with Strict Trust Policy for SPIFFE Identity Claim
data "aws_iam_policy_document" "workload_trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.identity_mesh.arn]
    }

    # Audience validation condition
    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_issuer_url, "https://", "")}:aud"
      values   = [var.oidc_client_id]
    }

    # Subject validation condition (Exact SPIFFE ID match)
    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_issuer_url, "https://", "")}:sub"
      values   = [
        "spiffe://${var.trust_domain}/ns/${var.target_namespace}/sa/${var.target_service_account}"
      ]
    }
  }
}

resource "aws_iam_role" "federated_workload_role" {
  name                 = "${var.workload_name}-federated-identity-role"
  assume_role_policy   = data.aws_iam_policy_document.workload_trust_policy.json
  max_session_duration = 3600

  tags = {
    Environment     = var.environment
    WorkloadName    = var.workload_name
    Namespace       = var.target_namespace
    SecurityPattern = "Zero-Secret-Federation"
  }
}

# 3. Least-Privilege IAM Policy for the workload
resource "aws_iam_policy" "workload_policy" {
  name        = "${var.workload_name}-least-privilege-policy"
  description = "Granular least-privilege permissions for authenticated workload"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyWithoutSecureTransport"
        Effect = "Deny"
        Action = "*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AllowTargetS3Operations"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::corporate-data-${var.environment}",
          "arn:aws:s3:::corporate-data-${var.environment}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "workload_attach" {
  role       = aws_iam_role.federated_workload_role.name
  policy_arn = aws_iam_policy.workload_policy.arn
}
