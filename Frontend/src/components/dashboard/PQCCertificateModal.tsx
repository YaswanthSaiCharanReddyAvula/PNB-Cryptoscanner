import React from "react";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ShieldCheck, Download } from "lucide-react";

export function PQCCertificateModal() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" className="border-primary/50 text-primary hover:bg-primary/10">
          <ShieldCheck className="w-4 h-4 mr-2" /> Generate PQC Certificate
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[600px] border-[#FBBC09]/50 bg-card p-0 overflow-hidden">
        <div className="p-8 relative">
          {/* Background pattern/glow */}
          <div className="absolute top-0 left-0 w-full h-2 bg-gradient-to-r from-transparent via-[#FBBC09] to-transparent opacity-80" />
          <div className="absolute -top-24 -right-24 w-48 h-48 bg-[#FBBC09]/10 rounded-full blur-3xl pointer-events-none" />
          
          <div className="text-center space-y-2 mb-8 relative z-10">
            <h2 className="text-2xl font-serif font-bold text-[#FBBC09] uppercase tracking-widest">
              Post Quantum Cryptography Ready
            </h2>
            <p className="text-[10px] tracking-widest text-muted-foreground uppercase mt-2">
              Issued by QSCAS — Quantum-Safe Cryptography Assessment System
            </p>
          </div>

          <div className="space-y-6 relative z-10">
            <div className="text-center">
              <p className="text-sm text-muted-foreground mb-1">This certifies that</p>
              <p className="text-xl font-semibold text-foreground">Verified Organization Infrastructure</p>
              <p className="text-xs text-primary font-mono mt-1">*.verified-domain.com</p>
            </div>

            <div className="flex justify-center my-6">
              <div className="relative">
                <div className="absolute inset-0 rounded-full animate-ping opacity-20 bg-[#FBBC09]" style={{ animationDuration: '3s' }} />
                <div className="w-24 h-24 rounded-full border-4 border-[#FBBC09] flex items-center justify-center bg-card shadow-[0_0_15px_rgba(251,188,9,0.3)]">
                  <ShieldCheck className="w-12 h-12 text-[#FBBC09]" />
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm border-t border-border/50 pt-6">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-widest mb-1">Date of Assessment</p>
                <p className="font-medium text-foreground">{new Date().toLocaleDateString()}</p>
              </div>
              <div className="text-right">
                <p className="text-xs text-muted-foreground uppercase tracking-widest mb-1">Algorithms Verified</p>
                <p className="font-mono text-xs text-primary">CRYSTALS-Kyber-768</p>
                <p className="font-mono text-xs text-primary">CRYSTALS-Dilithium-3</p>
              </div>
            </div>
            
            <div className="text-center border-t border-border/50 pt-4">
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Complies with NIST Standards FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). 
                Officially designated as Fully Quantum Safe against known cryptanalytic quantum attacks.
              </p>
            </div>
          </div>
          
        </div>
        <div className="bg-secondary/50 p-4 border-t border-border flex justify-end">
          <Button className="bg-[#FBBC09] hover:bg-[#FBBC09]/90 text-black font-semibold">
            <Download className="w-4 h-4 mr-2 text-black" /> Download Certificate
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
