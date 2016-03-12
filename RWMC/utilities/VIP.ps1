function White-Rabbit {
    Write-Host -object (("1*0½1*1½1*3½1*0½1*1½1*1½1*3½1*1½*1½1*2½1*3½1*1½1*1½1*1½1*9½1*10½1*11½1*11½1*10½1*12½1*1½1*13½1*14½1*15½1*1½1*12½1*14½1*16½1*13½1*15½1*1½1*17½1*18½1*19½1*19½1*16½1*13½1*1½1*20½1*21½1*22½1*0½1*1½1*1½0*1½1*5½1*1½1*7½1*1½1*1½1*1½1*1½1*1½1*1½1*1½1*23½1*18½1*27½1*24½1*18½1*15½1*25½1*15½1*26½1*8½1*28½1*29½1*18½1*16½1*11½1*6½1*30½1*10½1*29½1*0½1*6½1*5½1*1½1*8½1*1½1*7½1*6½1*1½1*0"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99"-split "T")[$matches[2]])"*$matches[1]}})-separator "" -ForegroundColor Yellow
}

function Clear-Chain ($chain) {
    $string = ""
    foreach ($c in $chain) {
        $string += $c        
    }
    return $string
}

function White-Rabbit1 {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*14½1*35½1*36½1*15½1*32½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-Rabbit42 {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*14½1*35½1*36½1*15½1*32½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[1]
    return $chain
}

function White-Rabbit2 {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*12½1*18½1*32½1*24½1*33½1*34½1*14½1*35½1*36½1*15½1*32½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[5]
    return $chain
}

function White-Rabbit3 {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*14½1*39½1*15½1*32½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-Rabbit4 {
    $chain = (("1*31½1*19½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*40½1*26½1*16½1*13½1*16½1*18½1*11½1*16½1*41½1*18½1*13½1*16½1*10½1*26½1*42½1*15½1*30½1*13½1*10½1*24"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}
function White-RabbitObs1 {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*28½1*4½1*23½1*36½1*15½1*32½1*43½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}
function White-RabbitOrWhat {
    $chain = (("1*31½1*31½1*1½1*12½1*31½1*16½1*28½1*15½1*32½1*13½1*34½1*11½1*4½1*44½1*10½1*28½1*45½1*15½1*32½1*32½1*44½1*16½1*32½1*13"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88T76T83"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}function White-RabbitOK {
    $chain = (("1*31½1*31½1*1½1*11½1*32½1*12½1*18½1*32½1*24½1*½1*39½1*34½1*14½1*35½1*36½1*15½1*32½1*37½1*15½1*38"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T117"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[9]
    return $chain
}

function White-RabbitPi {
    $chain = (("1*31½1*19½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*28½1*4½1*9½1*15½1*15½1*31½1*19½1*18½1*30½1*25"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

function White-RabbitCO {
    $chain = (("1*31½1*19½1*1½1*11½1*32½1*18½1*32½1*24½1*33½1*34½1*28½1*4½1*9½1*15½1*15½1*31½1*19½1*18½1*30½1*25"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = $chain[0]+$chain[1]
    return $chain
}

function White-RabbitContext {
    $chain = (("1*34½1*23½1*24½1*10½1*30½1*15½1*32½1*32½1*1½1*44½1*1½1*44½1*1½1*11½1*32½1*18½1*32½1*32½1*6½1*15½1*45½1*15"-split "½")-split "_"|%{if($_-match "(\d+)\*(\d+)"){"$([char][int]("10T32T47T92T95T40T46T41T64T70T111T108T119T116T104T101T105T82T97T98T58T45T41T112T114T107T110T98T103T109T99T100T115T118T33T51T68T75T121T65T73T122T86T88T48T120"-split "T")[$matches[2]])"*$matches[1]}})
    $chain = Clear-Chain ($chain)
    return $chain
}

White-Rabbit1