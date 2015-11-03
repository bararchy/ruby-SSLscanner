module ScanSSL
  class Export
    def self.pdf(file, data)
      Prawn::Document.generate(file) do
        text "Hello :-) This is my #{data}"
      end
    end

    def self.txt(file, data)
      ftxt = File.open("#{path}/#{file}", "a")
      ftxt.write(data)
      ftxt.close
    end

    def self.csv(file, data)
    end
  end
end
