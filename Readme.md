#Devsecops commands

##Trivy all
trivy image Imagename --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report.html
trivy image Imagename --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report.html --ignore-unfixed



##CDXgen and Grype:
cdxgen -r imagename -o sbom.json -t docker
cdxgen -r -o sbom.json
cdxgen -r /path -o sbom.json
WIND: type sbom.json | grype -o template -t html.tmpl > grype.html
Deb: cat sbom.json | grype -o template -t html.tmpl > grype.html


Azure repo image scanning:
az login
az acr login --name reposname
docker login reposname.azurecr.io
then scan the azure container images
trivy image imagerepo.azurecr.io/alpha.1.1.1 --scanners vuln,secret,misconfig --format template --template "@html.tpl" -o report_pdca_dap.html



