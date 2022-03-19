cmd_/home/devc/project/Module.symvers := sed 's/ko$$/o/' /home/devc/project/modules.order | scripts/mod/modpost  -a   -o /home/devc/project/Module.symvers -e -i Module.symvers   -T -
