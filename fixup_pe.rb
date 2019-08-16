def fixup_pe( file, flag_laa, flag_dep, flag_aslr, strip_symbols, fix_sizeof )

    begin
    
        f = File::open( file, 'rb' )

        data = f.read( f.stat.size )

        f.close()
        
        dirty                = false
        
        e_lfanew             = data[0x3C,4].unpack( 'V' ).first
        
        machine              = data[e_lfanew+4,2].unpack( 'v' ).first
        
        numberofsections     = data[e_lfanew+6,2].unpack( 'v' ).first
        
        pointertosymboltable = data[e_lfanew+12,4].unpack( 'V' ).first
        
        numberofsymbols      = data[e_lfanew+16,4].unpack( 'V' ).first
        
        characteristics      = data[e_lfanew+22,2].unpack( 'v' ).first

        filealignment        = data[e_lfanew+60,4].unpack( 'V' ).first

        sizeofheaders        = data[e_lfanew+84,4].unpack( 'V' ).first
        
        dllcharacteristics   = data[e_lfanew+94,2].unpack( 'v' ).first
        
        if( machine == 0x8664 ) # IMAGE_FILE_MACHINE_AMD64
        
            tls_va                 = { :value => data[e_lfanew+208,4].unpack( 'V' ).first, :offset => e_lfanew+208 }
            
            tls_sz                 = { :value => data[e_lfanew+212,4].unpack( 'V' ).first, :offset => e_lfanew+212 }

            expected_sizeofheaders = e_lfanew + 0x108 + (numberofsections * 0x28)
        elsif( machine == 0x014C ) # IMAGE_FILE_MACHINE_I386
        
            tls_va                 = { :value => data[e_lfanew+208-16,4].unpack( 'V' ).first, :offset => e_lfanew+208-16 }
            
            tls_sz                 = { :value => data[e_lfanew+212-16,4].unpack( 'V' ).first, :offset => e_lfanew+212-16 }
            
            expected_sizeofheaders = e_lfanew + 0xf8 + (numberofsections * 0x28)
        else
            raise "not an AMD64 or I386 PE binary."
        end
        
        if( flag_laa and machine == 0x014C )
        
            if( characteristics & 0x20 != 0x20 ) # IMAGE_FILE_LARGE_ADDRESS_AWARE
            
                data[e_lfanew+22,2] = [ characteristics | 0x20 ].pack( 'v' )
                
                dirty = true
            end
        end
        
        if( flag_dep )
        
            if( dllcharacteristics & 0x100 != 0x100 ) # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            
                dllcharacteristics = dllcharacteristics | 0x100
                
                data[e_lfanew+94,2] = [ dllcharacteristics ].pack( 'v' )
                
                dirty = true
            end
        end        
        
        if( flag_aslr )
        
            if( dllcharacteristics & 0x40 != 0x40 ) # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            
                dllcharacteristics = dllcharacteristics | 0x40
            
                data[e_lfanew+94,2] = [ dllcharacteristics ].pack( 'v' )
                
                dirty = true
            end
        end
        
        if( fix_sizeof )
        
            if( expected_sizeofheaders % filealignment != 0 )
            
                expected_sizeofheaders = expected_sizeofheaders - (expected_sizeofheaders % filealignment) + filealignment 
            end
            
            if( sizeofheaders != expected_sizeofheaders )
            
                sizeofheaders = expected_sizeofheaders
                
                data[e_lfanew+84,4] = [ sizeofheaders ].pack( 'V' )
                
                dirty = true
            end
        end
        
        if( strip_symbols )
        
            if( numberofsymbols != 0 )
            
                data[e_lfanew+16,4] = [ 0 ].pack( 'V' )
                
                dirty = true
            end
            
            if( pointertosymboltable != 0 )
            
                data[e_lfanew+12,4] = [ 0 ].pack( 'V' )
                
                data  = data[ 0, (pointertosymboltable - ( pointertosymboltable % filealignment )) ]
                
                dirty = true
            end
        end
        
        if( dirty )
        
            f = ::File::open( file, 'wb+' )
            
            f.write( data )
            
            f.close()
        end
        
    rescue
        return false
    end
    
    return true
end

if( $0 == __FILE__ )

    if( ARGV.length == 0 or ARGV.include?( '--help' ) or ARGV.include?( '-h' ) or ARGV.include?( '/h' ) or ARGV.include?( '/help' ) )
        
        $stdout.puts( "usage: fixup_pe.rb [/flag_laa] [/flag_dep] [/flag_aslr] [/strip_symbols] [/fix_sizeof] c:\\path\\to\\file.exe" )
       
       ::Kernel.exit( true )
    end

    file = nil
    
    flag_laa = false
    
    flag_dep = false
    
    flag_aslr = false
    
    strip_symbols = false
    
    fix_sizeof = false
    
    ARGV.each do | arg |
    
        arg = arg.downcase
        
        flag_laa = true if arg == '/flag_laa'
        
        flag_dep = true if arg == '/flag_dep'
        
        flag_aslr = true if arg == '/flag_aslr'
        
        strip_symbols = true if arg == '/strip_symbols'
        
        fix_sizeof = true if arg == '/fix_sizeof'
    end

    file = ARGV.last
   
    if( not ::File.exist?( file ) )
    
        $stderr.puts( "error: File '#{file}' not found." )
        
        ::Kernel.exit( false )
    end
    
    ::Kernel::exit( 
        fixup_pe( file, flag_laa, flag_dep, flag_aslr, strip_symbols, fix_sizeof ) 
    )
end
