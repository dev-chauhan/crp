cmd_/home/devc/project/mod/Module.symvers := sed 's/ko$$/o/' /home/devc/project/mod/modules.order | scripts/mod/modpost  -a   -o /home/devc/project/mod/Module.symvers -e -i Module.symvers   -T -
