data "aws_route53_zone" "selected" {
  zone_id = var.dashboard_domain
}

resource "aws_route53_record" "webservers" {
  zone_id  = data.aws_route53_zone.selected.zone_id
  name     = join(".", ["dashboard", data.aws_route53_zone.selected.name])
  type     = "A"
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = false
  }

  lifecycle {
    ignore_changes = [fqdn,id,name,records,ttl]
  }
}