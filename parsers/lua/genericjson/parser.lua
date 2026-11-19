function parse(input, emit)
  local doc = json.decode(input)
  if not doc then
    return
  end

  local top_tool = doc.tool or doc.name or "generic"
  local top_ver = doc.version or ""

  local items = doc
  if doc.findings and type(doc.findings) == "table" then
    items = doc.findings
  end

  if type(items) ~= "table" then
    return
  end

  for _, f in ipairs(items) do
    if type(f) == "table" and (f.title or f.rule_id or f.id) then
      local rule_id = f.rule_id or f.vuln_id_from_tool or f.id or f.title or "generic-finding"
      local title = f.title or rule_id
      local desc = f.description or title
      if f.mitigation and f.mitigation ~= "" then
        desc = desc .. "\n\nMitigation: " .. f.mitigation
      elseif f.remediation and f.remediation ~= "" then
        desc = desc .. "\n\nRemediation: " .. f.remediation
      end

      -- Category inference matching docs/05 and genericjson.go
      local cat = "sast"
      if f.category and f.category ~= "" then
        cat = string.lower(f.category)
      elseif f.secret and f.secret ~= "" then
        cat = "secret"
      elseif (f.purl and f.purl ~= "") or (f.component and f.component ~= "") then
        cat = "sca"
      elseif (f.url and f.url ~= "") or f.dynamic_finding then
        cat = "dast"
      elseif f.resource and f.resource ~= "" and (not f.file or f.file == "") then
        cat = "cspm"
      end

      local sev = string.lower(f.severity or "")
      if sev == "" then
        if f.cvssv3_score then
          local score = tonumber(f.cvssv3_score) or 0
          if score >= 9.0 then sev = "critical"
          elseif score >= 7.0 then sev = "high"
          elseif score >= 4.0 then sev = "medium"
          elseif score > 0 then sev = "low"
          else sev = "info"
          end
        else
          sev = "medium"
        end
      end

      local tool = f.tool or top_tool
      local family = "generic:" .. string.lower(string.gsub(tool, "%s+", "-"))

      local cwes = {}
      if f.cwe then
        if type(f.cwe) == "number" then
          table.insert(cwes, f.cwe)
        elseif type(f.cwe) == "string" then
          local n = string.match(f.cwe, "%d+")
          if n then table.insert(cwes, tonumber(n)) end
        elseif type(f.cwe) == "table" then
          for _, c in ipairs(f.cwe) do
            local n = tonumber(c) or tonumber(string.match(tostring(c), "%d+"))
            if n then table.insert(cwes, n) end
          end
        end
      end

      local vuln_ids = {}
      if f.cve and f.cve ~= "" then
        table.insert(vuln_ids, f.cve)
      end
      if f.vulnerability_ids and type(f.vulnerability_ids) == "table" then
        for _, v in ipairs(f.vulnerability_ids) do
          if type(v) == "string" then
            table.insert(vuln_ids, v)
          elseif type(v) == "table" and v.vulnerability_id then
            table.insert(vuln_ids, v.vulnerability_id)
          end
        end
      end

      local loc = {}
      if f.file or f.file_path then
        loc.code = {
          file_path = f.file or f.file_path,
          start_line = tonumber(f.line) or 1,
          end_line = tonumber(f.end_line)
        }
      end
      if f.url then
        loc.web = {
          normalized_url = f.url,
          method = f.method,
          parameter = f.param
        }
      end
      if f.purl or f.component then
        loc.package = {
          purl = f.purl,
          component_name = f.component or f.component_name,
          installed_version = f.version or f.component_version,
          fixed_version = f.fixed_version,
          manifest_path = f.manifest
        }
      end
      if f.resource then
        loc.resource = {
          address = f.resource,
          type = f.resource_type
        }
      end

      emit({
        rule_id = rule_id,
        title = title,
        description = desc,
        severity = sev,
        tool_severity = f.severity or sev,
        category = cat,
        scanner_family = family,
        scanner_version = top_ver,
        cwes = cwes,
        vuln_ids = vuln_ids,
        cvss_vector = f.cvssv3 or f.cvss_vector,
        secret_value = f.secret,
        location = loc
      })
    end
  end
end
