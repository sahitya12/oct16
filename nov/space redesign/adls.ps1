# .azure-pipelines/stages/adls.stage.yml

parameters:
  - name: adh_group
    type: string
  - name: adh_sub_group
    type: string
    default: ''
  - name: adh_subscription_type
    type: string
    default: nonprd
  - name: poolName
    type: string
  - name: agentName
    type: string
  - name: variableGroup
    type: string
    default: modernization_tfstate_backend_details

stages:
- stage: ADLS_Scan
  displayName: "ADLS ACL Scan (${{ parameters.adh_group }} / ${{ parameters.adh_subscription_type }})"

  variables:
    - group: ${{ parameters.variableGroup }}   # modernization_tfstate_backend_details

  jobs:
  - job: adls_acl_validation
    displayName: "ADLS ACL Validation"
    pool:
      name: ${{ parameters.poolName }}
      demands:
        - Agent.Name -equals ${{ parameters.agentName }}

    steps:
      - checkout: self

      - task: PowerShell@2
        displayName: "Run Scan-ADLS-Acls.ps1"
        inputs:
          targetType: 'inline'
          pwsh: true
          script: |
            Write-Host "=== Building params for Scan-ADLS-Acls.ps1 ==="

            # modernization_tfstate_backend_details should define:
            #   tenant_id
            #   backend_client_id
            #   backend_client_secret
            $params = @{
              TenantId              = "$(tenant_id)"
              ClientId              = "$(backend_client_id)"
              ClientSecret          = "$(backend_client_secret)"

              adh_group             = "${{ parameters.adh_group }}"
              adh_sub_group         = "${{ parameters.adh_sub_group }}"
              adh_subscription_type = "${{ parameters.adh_subscription_type }}"

              InputCsvPath          = "$(System.DefaultWorkingDirectory)/sanitychecks/inputs/adls_${{ parameters.adh_subscription_type }}_permissions.csv"
              OutputDir             = "$(Build.ArtifactStagingDirectory)/adls-acl"
              BranchName            = "$(Build.SourceBranchName)"
            }

            Write-Host "DEBUG: Parameter values passed to Scan-ADLS-Acls.ps1:"
            $params.GetEnumerator() | ForEach-Object {
              Write-Host "  $($_.Key) = $($_.Value)"
            }

            $scriptPath = "$(System.DefaultWorkingDirectory)/sanitychecks/scripts/Scan-ADLS-Acls.ps1"
            Write-Host "DEBUG: Script path = $scriptPath"

            if (-not (Test-Path -LiteralPath $scriptPath)) {
              Write-Error "Scan-ADLS-Acls.ps1 not found at $scriptPath"
              exit 1
            }

            & $scriptPath @params

            $exitCode = $LASTEXITCODE
            Write-Host "Scan-ADLS-Acls.ps1 exit code = $exitCode"

            if ($exitCode -ne 0) {
              Write-Error "Scan-ADLS-Acls.ps1 failed with exit code $exitCode"
              exit $exitCode
            }

            Write-Host "Scan-ADLS-Acls.ps1 finished successfully."
