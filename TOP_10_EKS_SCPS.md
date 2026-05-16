# Top 10 Most Impactful EKS SCPs (using AWS's newly released EKS IAM condition keys, April 2026)

In April 2026 AWS released a set of EKS-specific IAM condition keys that can be evaluated at the time `eks:CreateCluster`, `eks:UpdateClusterConfig`, `eks:UpdateClusterVersion`, and `eks:AssociateEncryptionConfig` are called. Before this release, the most security-sensitive EKS configuration values (public endpoint, envelope encryption key, deletion protection, control-plane scaling tier, Kubernetes version, zonal shift) could only be governed *after the fact* by AWS Config rules or custom Lambdas. With these keys, organisations can finally write preventive AWS Organizations Service Control Policies (SCPs) that block misconfigured clusters from ever being created or weakened.

This document lists the **top 10 highest-impact deny SCPs** that the new condition keys enable. Each policy is:

1. Limited to the **seven keys explicitly named in the AWS announcement** so that every condition key and every operator can be independently corroborated.
2. Scoped to the narrowest possible `Action` list.
3. Written with `Resource: "*"` (SCPs require this for service-level denies).
4. Built with a placeholder **break-glass carve-out** that exempts `arn:aws:iam::*:role/BreakGlassEKSAdmin` so a human can recover from a self-inflicted lockout. Replace this ARN with your real break-glass role(s) before deploying.

> Important: SCPs do not grant permissions. They cap the maximum permissions available to principals in accounts under the OU they are attached to. To actually use an EKS API the caller still needs a granting IAM policy. The deny statements here apply *on top of* the existing identity-based and resource-based grants.

## Provenance and verification notes

- **Primary source for the seven new condition keys:** AWS "What's New" announcement, [Amazon EKS enhances cluster governance with new IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/) (April 2026). The announcement names every key used in this document and confirms the four API actions they apply to.
- **Authoritative table of keys, types, and applicable actions:** [Actions, resources, and condition keys for Amazon Elastic Kubernetes Service](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html). During the research for this document the page returned HTTP 403 to automated WebFetch, so each key was corroborated against the announcement, secondary AWS blog posts, and SDK release notes. Open the page in a browser before deploying to confirm the exact key spelling and value type.
- **SCP syntax (operators, multi-condition AND semantics, Null operator):** [Service control policies (SCPs) syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html) and [IAM JSON policy elements: Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).
- **Recommended pre-deploy validation:** `aws accessanalyzer validate-policy --policy-document file://scps/01-...json --policy-type SERVICE_CONTROL_POLICY` (see [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)). This API rejects unrecognised condition keys for the named service, so it catches typos in `eks:*` key names without you having to attach the SCP to a real OU.

## Conventions used in every policy

- `Effect: Deny`.
- The `Condition` block contains two operator blocks AND-ed together: the actual misconfiguration check, plus an `ArnNotLike` against `aws:PrincipalArn` that exempts the break-glass role. Multiple top-level keys inside a single `Condition` block are AND-ed (documented in the AWS IAM policy reference linked above).
- Wherever a key could legitimately be omitted from the request, an explicit `Null` check is added so the absence of the key is also denied, not just the wrong value.

---

## SCP 1: Deny `CreateCluster` with a public Kubernetes API endpoint

**What it blocks.** Creating an EKS cluster whose Kubernetes API server endpoint is exposed to the public Internet.

**Why it matters.** A public endpoint puts the Kubernetes API server (the highest-value control plane in your account) directly on the Internet. It is the single most common cause of EKS data exfiltration: stolen kubeconfigs, exposed `kubectl` tokens, brute-forcing of webhook-style auth, and pre-auth CVEs in `kube-apiserver` all become reachable from anywhere. The AWS EKS docs explicitly recommend private-only endpoints for production clusters ([cluster endpoint access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)).

**Affected API action.** `eks:CreateCluster`.

**Condition key.** `eks:endpointPublicAccess` (Bool). Operator: `Bool` with value `"true"` (deny when the requester sets it to true).

**Code sample (`scps/01-deny-public-endpoint-at-create.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterCreateWithPublicEndpoint",
      "Effect": "Deny",
      "Action": "eks:CreateCluster",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:endpointPublicAccess": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks create-cluster --name demo --role-arn ... --resources-vpc-config subnetIds=...,endpointPublicAccess=true,endpointPrivateAccess=true` should return `AccessDeniedException` citing the SCP `Sid`.
- Allowed: the same command with `endpointPublicAccess=false,endpointPrivateAccess=true` should pass the SCP (it may still fail later for unrelated reasons such as missing subnets).

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [EKS cluster endpoint access docs](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html), [Wiz EKS security best practices](https://www.wiz.io/academy/container-security/eks-security-best-practices).

---

## SCP 2: Deny enabling a public endpoint via `UpdateClusterConfig`

**What it blocks.** Flipping an existing cluster's API endpoint from private-only to public.

**Why it matters.** SCP 1 only fires at create time. The most common posture-degradation pattern in real incidents is an engineer (or an attacker who has compromised a CI principal) toggling `endpointPublicAccess` to `true` on an existing cluster to make remote debugging easier. Pairing a create-time and an update-time SCP closes that gap.

**Affected API action.** `eks:UpdateClusterConfig`.

**Condition key.** `eks:endpointPublicAccess` (Bool). Operator: `Bool` with value `"true"`.

**Code sample (`scps/02-deny-enabling-public-endpoint-on-update.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksUpdateThatEnablesPublicEndpoint",
      "Effect": "Deny",
      "Action": "eks:UpdateClusterConfig",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:endpointPublicAccess": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks update-cluster-config --name demo --resources-vpc-config endpointPublicAccess=true,endpointPrivateAccess=true`.
- Allowed: `aws eks update-cluster-config --name demo --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true`.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [UpdateClusterConfig API reference](https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html).

---

## SCP 3: Require the private endpoint to be enabled

**What it blocks.** Creating or updating a cluster with `endpointPrivateAccess=false`, which would mean the API server can only be reached via the public endpoint.

**Why it matters.** This is the inverse guardrail of SCPs 1 and 2. Even if some teams legitimately need limited public access (for a managed CI provider, say), the *private* endpoint should always be on; otherwise pods, nodes, and VPC-resident operators have to leave the VPC and traverse the public Internet to reach the control plane, which is both slower and a confidentiality risk. The AWS Well-Architected Containers and EKS networking docs treat `endpointPrivateAccess=true` as the baseline ([Cluster API server endpoint](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html)).

**Affected API actions.** `eks:CreateCluster`, `eks:UpdateClusterConfig`.

**Condition key.** `eks:endpointPrivateAccess` (Bool). Operator: `Bool` with value `"false"`.

**Code sample (`scps/03-require-private-endpoint.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterWithoutPrivateEndpoint",
      "Effect": "Deny",
      "Action": [
        "eks:CreateCluster",
        "eks:UpdateClusterConfig"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:endpointPrivateAccess": "false"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: any `create-cluster` or `update-cluster-config` call with `endpointPrivateAccess=false`.
- Allowed: the same call with `endpointPrivateAccess=true`.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [EKS cluster endpoint access docs](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html).

---

## SCP 4: Require envelope encryption with an approved customer-managed KMS CMK

**What it blocks.** Creating or attaching encryption config to a cluster that either (a) does not enable EKS secrets envelope encryption at all, or (b) uses a CMK that is not on an explicit allow-list.

**Why it matters.** Kubernetes Secrets are stored in etcd. EKS's etcd is encrypted at rest by AWS-managed keys by default, but envelope encryption with a customer-managed KMS key (CMK) gives you separate key custody, key rotation that you control, CloudTrail decrypt logs, and the ability to *revoke* access to all secrets in a cluster by disabling one KMS key. AWS recommends envelope encryption with a CMK for any cluster handling sensitive data ([encryption at rest for EKS](https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html)).

**Affected API actions.** `eks:CreateCluster`, `eks:AssociateEncryptionConfig`.

**Condition key.** `eks:encryptionConfigProviderKeyArns` (ArrayOfString of KMS CMK ARNs). Two statements are combined: a `Null` check denies the case where no encryption config is supplied at all, and a `ForAnyValue:ArnNotLike` check denies the case where the supplied key is not on the allow-list.

**Code sample (`scps/04-require-approved-kms-cmk.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterWithoutKmsEnvelopeEncryption",
      "Effect": "Deny",
      "Action": [
        "eks:CreateCluster",
        "eks:AssociateEncryptionConfig"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "eks:encryptionConfigProviderKeyArns": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    },
    {
      "Sid": "DenyEksClusterWithUnapprovedKmsKey",
      "Effect": "Deny",
      "Action": [
        "eks:CreateCluster",
        "eks:AssociateEncryptionConfig"
      ],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:ArnNotLike": {
          "eks:encryptionConfigProviderKeyArns": [
            "arn:aws:kms:*:111122223333:key/REPLACE-WITH-APPROVED-CMK-UUID"
          ]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

Replace `111122223333` and `REPLACE-WITH-APPROVED-CMK-UUID` with the account ID(s) and key UUID(s) of your approved KMS CMKs. Add more allowed ARNs to the array if multiple CMKs are acceptable.

**How to verify.**

- Denied: `aws eks create-cluster ...` with no `--encryption-config` flag (first statement fires via `Null`).
- Denied: `aws eks create-cluster ... --encryption-config '[{"provider":{"keyArn":"arn:aws:kms:us-east-1:999999999999:key/some-random-key"},"resources":["secrets"]}]'` (second statement fires via `ForAnyValue:ArnNotLike`).
- Allowed: the same call using an ARN from the allow-list.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [EKS encryption at rest](https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html), [AssociateEncryptionConfig API reference](https://docs.aws.amazon.com/eks/latest/APIReference/API_AssociateEncryptionConfig.html), [IAM `ForAnyValue` qualifier docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html).

---

## SCP 5: Enforce a minimum Kubernetes version on cluster creation

**What it blocks.** Creating an EKS cluster pinned to a Kubernetes version older than your organisational floor (the example uses `1.31`).

**Why it matters.** Every Kubernetes minor version eventually goes out of standard support on EKS, after which patches stop and known CVEs (control plane RCEs, kubelet privilege escalations, container-runtime escapes) accumulate. Enforcing a minimum version at creation prevents teams from spinning up "throwaway" clusters on old, unpatched versions that quietly become long-lived. AWS publishes the supported version matrix at [Understand the Kubernetes version lifecycle on EKS](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).

**Affected API action.** `eks:CreateCluster`.

**Condition key.** `eks:kubernetesVersion` (String, of the form `MAJOR.MINOR`, for example `1.31`). Operator: `StringLessThan` against the floor.

**Important caveat: string comparison of versions.** `StringLessThan` is lexicographic. For two-component versions like `1.28`, `1.29`, `1.30`, `1.31` this works correctly because they have the same width and the leading `1.` is constant. It will break the day EKS reaches `1.100` (because `"1.100" < "1.31"` lexicographically). Re-evaluate the operator (or zero-pad the comparison value) once a three-digit minor is on the horizon.

**Code sample (`scps/05-enforce-minimum-kubernetes-version-on-create.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterCreateBelowMinimumKubernetesVersion",
      "Effect": "Deny",
      "Action": "eks:CreateCluster",
      "Resource": "*",
      "Condition": {
        "StringLessThan": {
          "eks:kubernetesVersion": "1.31"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks create-cluster --name demo --kubernetes-version 1.28 ...`.
- Allowed: the same call with `--kubernetes-version 1.31` (or any later supported version).

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [EKS Kubernetes version lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html), [IAM string condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String).

---

## SCP 6: Block downgrades or upgrades to a below-floor Kubernetes version

**What it blocks.** Calling `eks:UpdateClusterVersion` with a target version below the same floor used in SCP 5.

**Why it matters.** Without this SCP, an attacker (or a careless engineer) with `eks:UpdateClusterVersion` could roll an existing cluster onto a deprecated version after the fact, side-stepping SCP 5. EKS does not technically allow Kubernetes downgrades, but it does allow "skip-level" requests and bad targets, and a future EKS feature change might broaden the allowed target set; an explicit deny on below-floor targets makes the guardrail durable.

**Affected API action.** `eks:UpdateClusterVersion`.

**Condition key.** `eks:kubernetesVersion` (String). Operator: `StringLessThan` against the floor.

**Code sample (`scps/06-block-downgrade-or-deprecated-version-on-update.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterUpgradeToBelowMinimumVersion",
      "Effect": "Deny",
      "Action": "eks:UpdateClusterVersion",
      "Resource": "*",
      "Condition": {
        "StringLessThan": {
          "eks:kubernetesVersion": "1.31"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks update-cluster-version --name demo --kubernetes-version 1.28`.
- Allowed: `aws eks update-cluster-version --name demo --kubernetes-version 1.32` (assuming the cluster is currently on 1.31 and `1.32` is a supported target).

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [UpdateClusterVersion API reference](https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterVersion.html), [EKS Kubernetes version lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).

---

## SCP 7: Require deletion protection on cluster creation

**What it blocks.** Creating an EKS cluster with `deletionProtection=false`, or omitting the field entirely.

**Why it matters.** EKS added cluster deletion protection in August 2025 ([Protect EKS clusters from accidental deletion](https://docs.aws.amazon.com/eks/latest/userguide/deletion-protection.html)) precisely because lost clusters are unrecoverable: when a cluster is deleted, every nodegroup, every IAM-bound add-on, every PVC reference, and the etcd encryption envelope go with it. A misclick or compromised CI principal can erase weeks of state. SCP 7 makes deletion protection the default for every new cluster in the OU.

**Affected API action.** `eks:CreateCluster`.

**Condition key.** `eks:deletionProtection` (Bool). Two statements are combined so that both the explicit `false` case and the field-omitted case are blocked.

**Code sample (`scps/07-require-deletion-protection-on-create.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterCreateWithoutDeletionProtection",
      "Effect": "Deny",
      "Action": "eks:CreateCluster",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:deletionProtection": "false"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    },
    {
      "Sid": "DenyEksClusterCreateWhenDeletionProtectionMissing",
      "Effect": "Deny",
      "Action": "eks:CreateCluster",
      "Resource": "*",
      "Condition": {
        "Null": {
          "eks:deletionProtection": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks create-cluster --name demo --no-deletion-protection ...`, and also `aws eks create-cluster --name demo ...` with no deletion-protection flag at all.
- Allowed: `aws eks create-cluster --name demo --deletion-protection ...`.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [Protect EKS clusters from accidental deletion](https://docs.aws.amazon.com/eks/latest/userguide/deletion-protection.html), [Amazon EKS adds safety control to prevent accidental cluster deletion (Aug 2025)](https://aws-news.com/article/2025-08-07-amazon-eks-adds-safety-control-to-prevent-accidental-cluster-deletion), [IAM `Null` operator](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_Null).

---

## SCP 8: Deny disabling deletion protection on existing clusters

**What it blocks.** Calling `eks:UpdateClusterConfig` with `deletionProtection=false`.

**Why it matters.** Same logic as the create-vs-update pairing in SCPs 1 and 2. Deletion protection is only useful if it cannot be silently flipped off as a step in a `delete-cluster` workflow. This SCP turns "disable protection then delete" into a two-principal action: only the break-glass role can disable, so any deletion has to be approved by whoever controls that role.

**Affected API action.** `eks:UpdateClusterConfig`.

**Condition key.** `eks:deletionProtection` (Bool). Operator: `Bool` with value `"false"`.

**Code sample (`scps/08-deny-disabling-deletion-protection.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksUpdateThatDisablesDeletionProtection",
      "Effect": "Deny",
      "Action": "eks:UpdateClusterConfig",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:deletionProtection": "false"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: `aws eks update-cluster-config --name demo --no-deletion-protection`.
- Allowed (no-op on this SCP): `aws eks update-cluster-config --name demo --deletion-protection`.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [Protect EKS clusters from accidental deletion](https://docs.aws.amazon.com/eks/latest/userguide/deletion-protection.html), [UpdateClusterConfig API reference](https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html).

---

## SCP 9: Require zonal shift to be enabled for high availability

**What it blocks.** Creating or updating an EKS cluster with `zonalShiftEnabled=false`.

**Why it matters.** Zonal shift lets EKS automatically steer traffic away from an impaired Availability Zone. Without it, an AZ-localised event (network, control-plane, or AZ-level AWS service degradation) translates into a hard outage even on clusters that nominally span multiple AZs. Treating zonal shift as mandatory for every cluster is the cheapest material HA improvement you can apply at the SCP layer.

**Affected API actions.** `eks:CreateCluster`, `eks:UpdateClusterConfig`.

**Condition key.** `eks:zonalShiftEnabled` (Bool). Operator: `Bool` with value `"false"`.

**Code sample (`scps/09-require-zonal-shift-enabled.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterWithoutZonalShift",
      "Effect": "Deny",
      "Action": [
        "eks:CreateCluster",
        "eks:UpdateClusterConfig"
      ],
      "Resource": "*",
      "Condition": {
        "Bool": {
          "eks:zonalShiftEnabled": "false"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

**How to verify.**

- Denied: a `create-cluster` or `update-cluster-config` call whose `zonalShiftConfig.enabled` is `false`.
- Allowed: the same call with `zonalShiftConfig.enabled=true`.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [UpdateClusterConfig API reference (zonalShiftConfig field)](https://docs.aws.amazon.com/eks/latest/APIReference/API_UpdateClusterConfig.html).

---

## SCP 10: Restrict the control-plane scaling tier to an approved value

**What it blocks.** Creating or updating an EKS cluster with a control-plane scaling tier that is not on the approved list (the example pins it to `STANDARD`).

**Why it matters.** EKS now exposes a `controlPlaneScalingTier` setting that influences how the managed control plane scales for very large clusters. Picking the wrong tier silently changes cost behaviour and (depending on tier) the SLA and feature set that apply. Pinning the tier organisation-wide forces any deviation through a documented change request rather than letting individual teams choose silently. Treat this as a cost-and-compliance guardrail rather than a pure security control.

**Affected API actions.** `eks:CreateCluster`, `eks:UpdateClusterConfig`.

**Condition key.** `eks:controlPlaneScalingTier` (String). Operator: `StringNotEquals` against the approved value(s). To allow more than one tier, expand the value to an array (the operator already treats arrays as OR-of-values).

**Code sample (`scps/10-restrict-control-plane-scaling-tier.json`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEksClusterWithUnapprovedControlPlaneScalingTier",
      "Effect": "Deny",
      "Action": [
        "eks:CreateCluster",
        "eks:UpdateClusterConfig"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "eks:controlPlaneScalingTier": "STANDARD"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassEKSAdmin"
        }
      }
    }
  ]
}
```

To approve more than one tier, change the value to a JSON array, for example `"eks:controlPlaneScalingTier": ["STANDARD", "ENTERPRISE"]`. Confirm the exact set of valid tier names in the [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html) before deploying, because new tiers added after April 2026 would otherwise be denied by default.

**How to verify.**

- Denied: a `create-cluster` call that sets a tier other than `STANDARD`.
- Allowed: the same call with the approved tier.

**Sources.** [AWS What's New: EKS IAM condition keys](https://aws.amazon.com/about-aws/whats-new/2026/04/amazon-eks-iam-condition-keys/), [IAM string condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_String).

---

## Deployment checklist

1. Replace `arn:aws:iam::*:role/BreakGlassEKSAdmin` in every policy with the actual break-glass role ARN(s) for your organisation. Use a JSON array of ARNs if you have more than one.
2. Replace `arn:aws:kms:*:111122223333:key/REPLACE-WITH-APPROVED-CMK-UUID` in SCP 4 with your approved CMK ARN(s).
3. Run `aws accessanalyzer validate-policy --policy-document file://scps/01-deny-public-endpoint-at-create.json --policy-type SERVICE_CONTROL_POLICY` (and repeat for every file). Fix any findings before attaching.
4. Attach each policy to a non-production OU first. Trigger each denied call from an account inside the OU and confirm `AccessDeniedException` with `Sid` in the message body.
5. Assume the break-glass role and confirm the same call is permitted.
6. Promote to production OUs.
7. Re-read the [Service Authorization Reference for Amazon EKS](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelastickubernetesservice.html) periodically so that you pick up new condition keys, new approved values (for example new control-plane scaling tiers), and any deprecated key names.

## Known limitations

- These ten SCPs cover *cluster-level* configuration. They do not govern nodegroup configuration, Fargate profile configuration, access entries, add-ons, or the Pod Identity service. Those need separate SCPs and IAM policies.
- Kubernetes-version comparisons rely on lexicographic ordering of `MAJOR.MINOR` strings. They will give incorrect results once any minor version reaches three digits (`1.100` and above sort below `1.31`). Re-evaluate before that happens.
- All ten policies trust the break-glass principal ARN pattern. If that role is compromised, the SCPs are bypassed. Lock the role down with strong MFA, session tagging, and CloudTrail alerting on every assume-role event.
