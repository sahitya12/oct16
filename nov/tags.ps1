parameters:
  - name: adh_group
    type: string
    default: ''

  - name: adh_sub_group       # OPTIONAL – can be left empty
    type: string
    default: ''

  - name: adh_subscription_type
    type: string
    default: nonprd
    values:
      - nonprd
      - prd

  - name: poolName
    type: string
    default: 'Self-Hosted-Pool'

  - name: agentName
    type: string
    default: ''

stages:
- stage: rg_permissions
  # Keep displayName simple – don't try to do conditional concat here
  displayName: ${{ format('RG Permissions ({0} / {1})', parameters.adh_group, parameters.adh_subscription_type) }}
  condition: and(succeeded(), ne('${{ parameters.adh_group }}',''))

  jobs:
  - template: ../templates/job.powershell-with-az.yml
    parameters:
      displayName: 'RG Permissions (ByCustodian)'
      variableGroup: modernization_tfstate_backend_details
      scriptPath: '$(Build.SourcesDirectory)/sanitychecks/scripts/Scan-RG-Permissions-ByCustodian.ps1'
      workingDir: '$(Build.SourcesDirectory)/sanitychecks/scripts'

      arguments: >-
        -TenantId "$(tenant_id)"
        -ClientId "$(backend_client_id)"
        -ClientSecret "$(backend_client_secret)"
        -adh_group "${{ parameters.adh_group }}"
        -adh_sub_group "${{ parameters.adh_sub_group }}"
        -adh_subscription_type "${{ parameters.adh_subscription_type }}"
        -ProdCsvPath "$(Build.SourcesDirectory)/sanitychecks/inputs/prod_permissions.csv"
        -NonProdCsvPath "$(Build.SourcesDirectory)/sanitychecks/inputs/nonprod_permissions.csv"
        -OutputDir "$(Build.ArtifactStagingDirectory)/rg-permissions"
        -BranchName "$(Build.SourceBranchName)"

      artifactName: 'rg-permissions'
      publishPath: '$(Build.ArtifactStagingDirectory)/rg-permissions'
      poolName: ${{ parameters.poolName }}
      agentName: ${{ parameters.agentName }}
