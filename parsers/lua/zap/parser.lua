function parse(input, emit)
  local doc = json.decode(input)
  if not doc or not doc.site then
    return
  end

  for _, site in ipairs(doc.site) do
    local site_name = site["@name"] or ""
    if site.alerts then
      for _, alert in ipairs(site.alerts) do
        local cwes = {}
        if alert.cweid and alert.cweid ~= "" and alert.cweid ~= "0" then
          local num = tonumber(alert.cweid)
          if num and num > 0 then
            table.insert(cwes, num)
          end
        end

        local sev = "medium"
        local code = tostring(alert.riskcode)
        if code == "3" then sev = "high"
        elseif code == "2" then sev = "medium"
        elseif code == "1" then sev = "low"
        elseif code == "0" then sev = "info"
        end

        local title = alert.alert or alert.name or ("ZAP Alert " .. (alert.pluginId or "unknown"))
        local desc = alert.desc or ""
        if alert.solution and alert.solution ~= "" then
          desc = desc .. "\n\nSolution: " .. alert.solution
        end

        local instances = alert.instances
        if instances and #instances > 0 then
          for _, inst in ipairs(instances) do
            local target_url = inst.uri
            if not target_url or target_url == "" then
              target_url = site_name
            end

            local inst_desc = desc
            if inst.evidence and inst.evidence ~= "" then
              inst_desc = inst_desc .. "\n\nEvidence: " .. inst.evidence
            end

            emit({
              rule_id = alert.pluginId or "zap-alert",
              rule_name = title,
              title = title,
              description = inst_desc,
              severity = sev,
              tool_severity = alert.riskdesc or sev,
              category = "dast",
              scanner_family = "zap",
              cwes = cwes,
              location = {
                web = {
                  normalized_url = target_url,
                  parameter = inst.param or "",
                  method = inst.method or ""
                }
              }
            })
          end
        else
          emit({
            rule_id = alert.pluginId or "zap-alert",
            rule_name = title,
            title = title,
            description = desc,
            severity = sev,
            tool_severity = alert.riskdesc or sev,
            category = "dast",
            scanner_family = "zap",
            cwes = cwes,
            location = {
              web = {
                normalized_url = site_name
              }
            }
          })
        end
      end
    end
  end
end
