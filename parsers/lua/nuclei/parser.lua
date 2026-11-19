function parse(input, emit)
  for line in string.gmatch(input, "[^\r\n]+") do
    line = string.match(line, "^%s*(.-)%s*$")
    if line ~= "" then
      local entry = json.decode(line)
      if entry and entry["template-id"] then
        local info = entry.info or {}
        local cwes = {}
        if info.classification and info.classification["cwe-id"] then
          for _, c in ipairs(info.classification["cwe-id"]) do
            local num = string.match(c, "%d+")
            if num then table.insert(cwes, tonumber(num)) end
          end
        end

        local target_url = entry["matched-at"]
        if not target_url or target_url == "" then
          target_url = entry.host or ""
        end

        local title = info.name or entry["template-id"]
        local desc = info.description or title
        if info.remediation and info.remediation ~= "" then
          desc = desc .. "\n\nRemediation: " .. info.remediation
        end

        local cvss = ""
        if info.classification and info.classification["cvss-metrics"] then
          cvss = info.classification["cvss-metrics"]
        end

        emit({
          rule_id = entry["template-id"],
          rule_name = info.name or entry["template-id"],
          title = title,
          description = desc,
          severity = string.lower(info.severity or "medium"),
          tool_severity = info.severity or "medium",
          category = "dast",
          scanner_family = "nuclei",
          cwes = cwes,
          cvss_vector = cvss,
          location = {
            web = {
              normalized_url = target_url
            }
          }
        })
      end
    end
  end
end
