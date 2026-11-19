function parse(input, emit)
  local doc = json.decode(input)
  if doc and doc.results then
    for _, r in ipairs(doc.results) do
      local cwes = {}
      if r.issue_cwe and r.issue_cwe.id then
        table.insert(cwes, r.issue_cwe.id)
      end
      emit({
        rule_id = r.test_id or "bandit-rule",
        title = r.issue_text or r.test_name or "Bandit finding",
        description = r.issue_text,
        severity = string.lower(r.issue_severity or "medium"),
        tool_severity = r.issue_severity or "MEDIUM",
        category = "sast",
        scanner_family = "bandit",
        cwes = cwes,
        location = {
          code = {
            file_path = r.filename,
            start_line = r.line_number
          }
        }
      })
    end
  end
end
