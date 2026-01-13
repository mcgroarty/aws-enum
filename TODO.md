# TODO

## Route53 DNS Audit Feature

**Goal**: Detect dangling DNS records and external/third-party targets that could indicate subdomain takeover risks or shadow IT.

### The Problem

Route53 records can point to:
- **A records** → IP addresses (EC2, ELB, on-prem, third-party)
- **CNAME records** → Domain names (ELB DNS, CloudFront, external services)
- **ALIAS records** → AWS resources (safer - they fail if resource is deleted)

We need to identify:
1. Records pointing to resources outside our AWS accounts
2. Dangling records pointing to deleted AWS resources (subdomain takeover risk)
3. External/third-party services (shadow IT visibility)

### Implementation Phases

#### Phase 1: Show Records with External Detection (Simple, High Value)

Add `--show-records` flag to `route53` command:
- List all DNS records per zone
- Pattern-match CNAME targets against known AWS patterns:
  ```
  *.elb.amazonaws.com         → Load Balancers
  *.elb.*.amazonaws.com       → Regional ELBs  
  *.cloudfront.net            → CloudFront
  *.s3.amazonaws.com          → S3
  *.rds.amazonaws.com         → RDS
  *.cache.amazonaws.com       → ElastiCache
  ```
- Flag any CNAME not matching `*.amazonaws.com` or `*.aws` as 🔶 External

**Output example:**
```
=== Production (123456789012) ===
  Hosted Zones:
    example.com (Z1234) public 42 records
      A     www.example.com          → 52.1.2.3
      CNAME api.example.com          → my-alb-123.us-west-2.elb.amazonaws.com
      CNAME mail.example.com         → mailgun.org                              🔶 External
      CNAME shop.example.com         → shops.myshopify.com                      🔶 External
```

#### Phase 2: Cross-Reference ELBs (Detect Dangling)

Verify AWS resource CNAMEs actually exist:
- We already enumerate ELBs across all accounts
- Build a set of all known ELB DNS names
- For any CNAME → `*.elb.amazonaws.com`, check if ELB exists
- Flag as 🔴 Dangling if not found

**Requires**: Running ELB enumeration first (or caching results)

#### Phase 3: IP Audit

For A records pointing to public IPs:
- Enumerate all Elastic IPs across accounts
- Enumerate all EC2 public IPs
- Cross-reference A record IPs against inventory
- Flag unknown IPs as 🔶 Unknown

**Complexity**: EC2 public IPs can be dynamic; Elastic IPs are more reliable.

### Technical Notes

- Route53 `ListResourceRecordSets` is paginated
- ALIAS records have `AliasTarget` instead of `ResourceRecords`
- Consider rate limiting for large zones
- May want `--external-only` filter to reduce noise

### AWS Patterns Reference

```python
AWS_PATTERNS = [
    r'\.elb\.amazonaws\.com$',
    r'\.elb\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$',
    r'\.cloudfront\.net$',
    r'\.s3\.amazonaws\.com$',
    r'\.s3-[a-z]+-[a-z]+-\d\.amazonaws\.com$',
    r'\.rds\.amazonaws\.com$',
    r'\.cache\.amazonaws\.com$',
    r'\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com$',  # API Gateway
    r'\.awsglobalaccelerator\.com$',
]
```

### Related Reading

- [Subdomain Takeover on AWS](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html)
- OWASP Subdomain Takeover documentation

---

## ECS Public-Facing Detection

**Goal**: Identify which ECS tasks are publicly accessible (exposed to the internet).

### The Problem

ECS tasks can be exposed via:
1. **Direct public IP** - Task with `assignPublicIp: ENABLED` in a public subnet
2. **Load Balancer** - Task registered to an ELB target group behind a public-facing ALB/NLB
3. **API Gateway** - VPC Link to private NLB (harder to trace)

Current `ecs` command shows tasks but doesn't indicate public exposure.

### Implementation Phases

#### Phase 1: Network Details (`--show-network`)

Add network information to task output:
- Parse `networkBindings` and `networkInterfaces` from task details
- Show private IP (always present)
- Show public IP (if `assignPublicIp: ENABLED`)

**API calls needed:**
- Already have task details from `ecs describe-tasks`
- ENI details may need `ec2 describe-network-interfaces` for public IP

**Output example:**
```
    Task abc123 (web:42) RUNNING 2h
      Private: 10.0.1.50
      Public:  54.1.2.3  ← Direct exposure
```

#### Phase 2: ELB Cross-Reference (`--show-exposure`)

Determine if tasks are behind load balancers:

1. **Get target groups for ECS services:**
   ```
   ecs describe-services → loadBalancers[].targetGroupArn
   ```

2. **Get targets in each target group:**
   ```
   elbv2 describe-target-health --target-group-arn <arn>
   ```

3. **Match task private IPs to target group targets**

4. **Check if parent load balancer is internet-facing:**
   ```
   elbv2 describe-load-balancers → Scheme: "internet-facing" vs "internal"
   ```

**Output example:**
```
    Task abc123 (web:42) RUNNING 2h
      Private: 10.0.1.50
      Exposed via: my-public-alb (internet-facing)  🌐 PUBLIC
    
    Task def456 (worker:10) RUNNING 5h
      Private: 10.0.2.100
      Exposed via: internal-api-nlb (internal)      🔒 INTERNAL
```

#### Phase 3: Security Group Analysis (Optional)

For direct public IP exposure, check security groups:
- Get ENI security groups from task network interface
- Check for `0.0.0.0/0` or `::/0` ingress rules
- Report open ports

**API calls:**
```
ec2 describe-security-groups --group-ids <sg-ids>
```

**Output example:**
```
    Task abc123 (web:42) RUNNING 2h
      Public: 54.1.2.3
      SG ingress: 80/tcp from 0.0.0.0/0, 443/tcp from 0.0.0.0/0  ⚠️ OPEN
```

### Technical Notes

- ECS services can have multiple target groups (blue/green, multiple listeners)
- Fargate tasks may not have traditional security groups visible
- Need to handle both EC2 and Fargate launch types
- Consider caching ELB data if running multiple commands

### Data Flow

```
ECS Service
    ↓
loadBalancers[].targetGroupArn
    ↓
Target Group → describe-target-health → IP:port targets
    ↓
Match task private IP
    ↓
describe-load-balancers → Scheme (internet-facing/internal)
```

### CLI Options

```
--show-network     Show task network details (private/public IPs)
--show-exposure    Cross-reference with ELBs to show public exposure
--public-only      Only show publicly exposed tasks
```

#### Phase 4: Indirect Exposure via CDN/API Gateway (Optional)

ALBs with `Scheme: internal` can still be publicly accessible if fronted by:

1. **CloudFront** - CDN with internal ALB as origin (most likely)
2. **API Gateway** - VPC Link to internal NLB
3. **Global Accelerator** - Anycast IPs routing to ALB/NLB

**CloudFront detection (highest priority):**
```
cloudfront list-distributions
  → Origins[].DomainName
  → Match against known ALB DNS names
```

**API Gateway detection:**
```
apigateway get-rest-apis
apigatewayv2 get-apis
apigateway get-vpc-links / apigatewayv2 get-vpc-links
  → Find NLB targets
```

**Global Accelerator detection:**
```
globalaccelerator list-accelerators
  → list-listeners
  → list-endpoint-groups
  → Match ALB/NLB ARNs
```

**Output example:**
```
    Task abc123 (web:42) RUNNING 2h
      Private: 10.0.1.50
      Exposed via: internal-alb (internal)
        ↳ CloudFront: d1234.cloudfront.net  🌐 PUBLIC
```

This would catch cases where internal ALBs are actually internet-accessible through AWS edge services.
